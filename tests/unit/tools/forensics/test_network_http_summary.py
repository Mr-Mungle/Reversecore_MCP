"""Tests for pcap_http_summary, the pcap_reconstruct_stream output modes and
the HTTP parsing helpers.

These tests build small real captures with Scapy instead of mocking packets,
so TCP reassembly and HTTP parsing are exercised end to end.
"""

from __future__ import annotations

import hashlib

import pytest

from reversecore_mcp.tools.forensics import _http_summary
from reversecore_mcp.tools.forensics.network import (
    pcap_http_summary,
    pcap_reconstruct_stream,
)

scapy = pytest.importorskip("scapy.all")

CLIENT = "10.0.0.5"
SERVER = "10.0.0.80"


def _tcp_session(sport, request, response=None, base_time=1700000000.0, chunk=1400):
    """Build the packets of one TCP session: handshake, request, optional response, FIN."""
    IP, TCP, Raw = scapy.IP, scapy.TCP, scapy.Raw
    client_seq, server_seq = 1000, 5000
    packets = [
        IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=80, flags="S", seq=client_seq),
        IP(src=SERVER, dst=CLIENT)
        / TCP(sport=80, dport=sport, flags="SA", seq=server_seq, ack=client_seq + 1),
    ]
    client_seq += 1
    server_seq += 1
    for offset in range(0, len(request), chunk):
        piece = request[offset : offset + chunk]
        packets.append(
            IP(src=CLIENT, dst=SERVER)
            / TCP(sport=sport, dport=80, flags="PA", seq=client_seq, ack=server_seq)
            / Raw(load=piece)
        )
        client_seq += len(piece)
    if response is not None:
        packets.append(
            IP(src=SERVER, dst=CLIENT)
            / TCP(sport=80, dport=sport, flags="PA", seq=server_seq, ack=client_seq)
            / Raw(load=response)
        )
        server_seq += len(response)
    packets.append(
        IP(src=SERVER, dst=CLIENT)
        / TCP(sport=80, dport=sport, flags="FA", seq=server_seq, ack=client_seq)
    )
    for index, packet in enumerate(packets):
        packet.time = base_time + index * 0.001
    return packets


def _multipart(fields, boundary=b"XyZ"):
    body = b""
    for name, value in fields:
        body += (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n' + value + b"\r\n"
        )
    body += b"--" + boundary + b"--\r\n"
    headers = (
        b"POST /upload.php HTTP/1.1\r\nHost: lab\r\n"
        b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
    )
    return headers + body


OK_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nServer: test\r\nContent-Length: 2\r\n"
    b"Set-Cookie: PHPSESSID=abcdef123456; path=/\r\n\r\nOK"
)
LEAK_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
    b"Set-Cookie: PHPSESSID=%10%00%00%00%00%00%00%00%60%1Bg%FE%FF%7F%00%00; path=/\r\n\r\nOK"
)


@pytest.fixture()
def lab_pcap(workspace_dir, patched_workspace_config):
    """Three sessions: normal upload, deep watched field, no response + leaked cookie."""
    normal = _multipart([(b"PHPSESSID", b"abc"), (b"PHP_SESSION_UPLOAD_PROGRESS", b"x")])
    filler = [(f"f{i:04d}".encode(), b"A" * 200) for i in range(600)]
    deep = _multipart(filler + [(b"PHP_SESSION_UPLOAD_PROGRESS", b"x")])
    packets = (
        _tcp_session(40001, normal, OK_RESPONSE, base_time=1700000000.0)
        + _tcp_session(40002, deep, LEAK_RESPONSE, base_time=1700000001.0)
        + _tcp_session(40003, normal, None, base_time=1700000002.0)
    )
    path = workspace_dir / "lab.pcap"
    scapy.wrpcap(str(path), packets)
    return str(path), deep


# ── HTTP helpers ──────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_parse_http_messages_handles_pipelining_and_chunked():
    stream = (
        b"POST /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"
        b"POST /b HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nxyz\r\n0\r\n\r\n"
        b"GET /c HTTP/1.1\r\nHost: x\r\n\r\n"
    )
    messages = _http_summary.parse_http_messages(stream, "request")
    assert [m["start_line"] for m in messages] == [
        "POST /a HTTP/1.1",
        "POST /b HTTP/1.1",
        "GET /c HTTP/1.1",
    ]
    assert messages[0]["body_bytes"] == 3
    assert messages[1]["chunked"] and messages[1]["body_bytes"] == 3
    assert all(m["complete"] for m in messages)


@pytest.mark.unit
def test_parse_http_responses_respects_head_and_no_body_statuses():
    stream = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"
        b"HTTP/1.1 304 Not Modified\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    )
    messages = _http_summary.parse_http_messages(stream, "response", ["HEAD", "GET", "GET"])
    assert [m["status_code"] for m in messages] == [200, 304, 200]
    assert [m["body_bytes"] for m in messages] == [0, 0, 2]


@pytest.mark.unit
def test_summarize_multipart_compresses_runs_and_reports_watched_offset():
    raw = _multipart([(f"p{i}".encode(), b"v") for i in range(30)] + [(b"target", b"x")])
    body = raw.split(b"\r\n\r\n", 1)[1]
    summary = _http_summary.summarize_multipart(
        body, b"multipart/form-data; boundary=XyZ", ["target", "absent"], max_runs=5
    )
    assert summary["part_count"] == 31
    assert summary["distinct_field_names"] == 31
    assert len(summary["field_runs"]) == 6
    assert summary["field_runs"][-1]["field"] == "<more>"
    assert summary["field_runs"][-1]["count"] == 26
    assert summary["watched_field_offsets"]["target"] == body.find(
        b'--XyZ\r\nContent-Disposition: form-data; name="target"'
    )
    assert summary["watched_field_offsets"]["absent"] is None


@pytest.mark.unit
def test_set_cookie_anomalies_flags_binary_but_not_normal_tokens():
    findings = _http_summary.set_cookie_anomalies(
        [b"PHPSESSID=abcdef0123456789; path=/", b"PHPSESSID=%00%01%02%7F; path=/"]
    )
    assert len(findings) == 1
    assert findings[0]["cookie"] == "PHPSESSID"
    assert findings[0]["non_printable_bytes"] == 4


# ── pcap_http_summary ─────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_http_summary_flags_signals(lab_pcap):
    path, _ = lab_pcap
    result = await pcap_http_summary(
        path, watch_fields=["PHP_SESSION_UPLOAD_PROGRESS"], inspection_window=100_000
    )
    assert result.status == "success"
    data = result.data
    assert data["totals"]["http_flows"] == 3
    assert data["totals"]["no_response"] == 1
    assert data["totals"]["anomalous_set_cookie"] == 1

    normal, deep, silent = data["transactions"]
    assert normal["flags"] == []
    assert normal["response"]["status_code"] == 200
    assert normal["request"]["multipart"]["part_count"] == 2

    assert "anomalous_set_cookie" in deep["flags"]
    assert "watched_field_beyond_inspection_window" in deep["flags"]
    assert deep["request"]["fields_beyond_inspection_window"] == ["PHP_SESSION_UPLOAD_PROGRESS"]

    assert silent["response"] is None
    assert "no_response" in silent["flags"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_http_summary_never_returns_field_values(lab_pcap):
    path, _ = lab_pcap
    result = await pcap_http_summary(path)
    assert b"A" * 50 not in str(result.data).encode()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pcap_http_summary_port_filter_and_validation(lab_pcap):
    path, _ = lab_pcap
    filtered = await pcap_http_summary(path, ports=[8080])
    assert filtered.data["totals"].get("http_flows", 0) == 0
    assert filtered.data["totals"]["filtered_flows"] == 3

    bad = await pcap_http_summary(path, max_transactions=0)
    assert bad.status == "error"
    bad_port = await pcap_http_summary(path, ports=[70000])
    assert bad_port.status == "error"


# ── pcap_reconstruct_stream output modes ──────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_reconstruct_summary_mode_omits_hex(lab_pcap):
    path, _ = lab_pcap
    result = await pcap_reconstruct_stream(
        path, CLIENT, SERVER, 80, src_port=40001, output_mode="summary"
    )
    assert result.status == "success"
    data = result.data
    assert data["hex_dump"] == ""
    forward = data["forward_stream"]
    assert "hex_dump" not in forward["segments"][0]
    assert len(forward["sha256"]) == 64
    assert forward["preview_printable"].startswith("POST /upload.php")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_reconstruct_file_mode_writes_inside_workspace(lab_pcap, workspace_dir):
    path, deep = lab_pcap
    result = await pcap_reconstruct_stream(
        path,
        CLIENT,
        SERVER,
        80,
        src_port=40002,
        output_mode="file",
        output_dir="carved",
    )
    assert result.status == "success"
    written = result.data["forward_stream"]["file"]
    assert written["bytes"] == len(deep)
    assert written["sha256"] == hashlib.sha256(deep).hexdigest()
    carved = workspace_dir / "carved"
    assert carved.is_dir()
    assert (carved / written["path"].rsplit("/", 1)[-1]).read_bytes() == deep


@pytest.mark.unit
@pytest.mark.asyncio
async def test_reconstruct_rejects_bad_mode_and_traversal(lab_pcap):
    path, _ = lab_pcap
    bad_mode = await pcap_reconstruct_stream(
        path, CLIENT, SERVER, 80, src_port=40001, output_mode="raw"
    )
    assert bad_mode.status == "error"
    traversal = await pcap_reconstruct_stream(
        path,
        CLIENT,
        SERVER,
        80,
        src_port=40001,
        output_mode="file",
        output_dir="../../etc",
    )
    assert traversal.status == "error"
    assert traversal.error.code == "PATH_TRAVERSAL_DETECTED"
    bad_scope = await pcap_reconstruct_stream(
        path, CLIENT, SERVER, 80, src_port=40001, packet_scope="all"
    )
    assert bad_scope.status == "error"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_reconstruct_per_direction_caps(lab_pcap):
    path, _ = lab_pcap
    result = await pcap_reconstruct_stream(
        path,
        CLIENT,
        SERVER,
        80,
        src_port=40002,
        max_bytes_c2s=100,
        max_bytes_s2c=10_000,
    )
    data = result.data
    assert data["forward_stream"]["payload_bytes"] == 100
    assert data["forward_stream"]["truncated"] is True
    assert data["reverse_stream"]["truncated"] is False


@pytest.mark.unit
@pytest.mark.asyncio
async def test_reconstruct_flow_scope_reaches_late_flows(lab_pcap):
    path, _ = lab_pcap
    # With file scope, a small max_packets stops before the third session starts.
    file_scoped = await pcap_reconstruct_stream(
        path, CLIENT, SERVER, 80, src_port=40003, max_packets=20
    )
    assert file_scoped.data["payload_bytes"] == 0
    flow_scoped = await pcap_reconstruct_stream(
        path, CLIENT, SERVER, 80, src_port=40003, max_packets=20, packet_scope="flow"
    )
    assert flow_scoped.data["payload_bytes"] > 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_reconstruct_flow_scope_caps_selected_flow_only(lab_pcap):
    path, _ = lab_pcap
    # Session 40002 is ~110 packets; a flow-scoped cap of 5 truncates it.
    capped = await pcap_reconstruct_stream(
        path, CLIENT, SERVER, 80, src_port=40002, max_packets=5, packet_scope="flow"
    )
    assert capped.data["truncated"] is True
    assert 0 < capped.data["payload_bytes"] < 5 * 1400


@pytest.mark.unit
def test_parse_http_messages_folded_headers_and_malformed_lines():
    stream = (
        b"POST /x HTTP/1.1\r\nX-Long: first\r\n second part\r\nno-colon-line\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    (message,) = _http_summary.parse_http_messages(stream, "request")
    headers = dict(message["headers"])
    assert headers["x-long"] == b"first second part"
    assert "no-colon-line" not in headers


@pytest.mark.unit
def test_parse_http_messages_reports_incomplete_capture():
    truncated_headers = b"POST /x HTTP/1.1\r\nHost: lab\r\nContent-Le"
    (message,) = _http_summary.parse_http_messages(truncated_headers, "request")
    assert message["complete"] is False
    assert message["start_line"] == "POST /x HTTP/1.1"

    short_body = b"POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\nonly-this"
    (message,) = _http_summary.parse_http_messages(short_body, "request")
    assert message["complete"] is False
    assert message["body_bytes"] == len(b"only-this")

    cut_chunk = b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nabc"
    (message,) = _http_summary.parse_http_messages(cut_chunk, "request")
    assert message["chunked"] and message["complete"] is False

    bad_chunk = b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"
    (message,) = _http_summary.parse_http_messages(bad_chunk, "request")
    assert message["complete"] is False


@pytest.mark.unit
def test_summarize_multipart_without_boundary_returns_none():
    assert _http_summary.summarize_multipart(b"data", b"multipart/form-data", []) is None
