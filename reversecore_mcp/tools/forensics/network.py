"""Network forensics tools backed by Scapy for PCAP analysis.

Pure Python implementation using Scapy — no external CLI dependencies,
fully container-friendly. Gracefully degrades if Scapy is not installed.
"""

import asyncio
import collections
import datetime
import hashlib
import re
from pathlib import Path
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import get_workspace_config, validate_file_path
from reversecore_mcp.tools.forensics import _http_summary

logger = get_logger(__name__)

# Common suspicious ports associated with C2 and malware communication
_SUSPICIOUS_PORTS = {
    4444,
    4445,
    5555,
    6666,
    7777,
    8080,
    8443,
    8888,
    9001,
    9002,
    31337,
    65535,
    1337,
    1234,
    12345,
    54321,
    6667,
    6697,
}

# Known C2 framework beacon intervals (seconds) for detection
_BEACON_INTERVALS_SEC = [60, 120, 180, 240, 300, 600]

# Minimum packet count per host to consider as beaconing
_BEACON_MIN_PACKETS = 5
_STREAM_OUTPUT_MODES = frozenset({"hex", "summary", "file"})
_TCP_SEQUENCE_MASK = (1 << 32) - 1
_TCP_SEQUENCE_HALF = 1 << 31


def _reassemble_tcp_payloads(
    payload_segments: list[tuple[int, bytes]], max_bytes: int
) -> dict[str, Any]:
    """Reassemble one TCP direction by sequence number.

    Overlapping bytes keep the data from the earliest sequence segment. Exact
    duplicate segments and conflicting overlap bytes are reported separately.
    Gaps remain separate runs instead of being filled with fabricated bytes.
    """
    if not payload_segments:
        return {
            "segments": [],
            "gaps": [],
            "payload_bytes": 0,
            "overlap_bytes": 0,
            "retransmission_count": 0,
            "conflicting_overlap_bytes": 0,
            "truncated": False,
        }

    max_bytes = max(0, max_bytes)
    anchor = int(payload_segments[0][0]) & _TCP_SEQUENCE_MASK
    positioned = []
    for capture_index, (sequence, payload) in enumerate(payload_segments):
        sequence = int(sequence) & _TCP_SEQUENCE_MASK
        relative_sequence = (
            (sequence - anchor + _TCP_SEQUENCE_HALF) & _TCP_SEQUENCE_MASK
        ) - _TCP_SEQUENCE_HALF
        positioned.append((relative_sequence, capture_index, bytes(payload)))
    positioned.sort(key=lambda item: (item[0], item[1]))

    runs: list[dict[str, Any]] = []
    payload_byte_count = 0
    overlap_byte_count = 0
    retransmission_count = 0
    conflicting_overlap_byte_count = 0
    truncated = False

    for sequence_offset, _, payload in positioned:
        if not payload:
            continue

        if not runs or sequence_offset > runs[-1]["end"]:
            available = max_bytes - payload_byte_count
            if available <= 0:
                truncated = True
                continue
            accepted = payload[:available]
            runs.append(
                {
                    "start": sequence_offset,
                    "end": sequence_offset + len(accepted),
                    "payload": bytearray(accepted),
                }
            )
            payload_byte_count += len(accepted)
            if len(accepted) < len(payload):
                truncated = True
            continue

        run = runs[-1]
        overlap_length = max(0, min(run["end"], sequence_offset + len(payload)) - sequence_offset)
        if overlap_length:
            payload_offset = sequence_offset - run["start"]
            existing = run["payload"][payload_offset : payload_offset + overlap_length]
            overlapping_payload = payload[:overlap_length]
            conflicting = sum(
                existing_byte != incoming_byte
                for existing_byte, incoming_byte in zip(existing, overlapping_payload, strict=True)
            )
            overlap_byte_count += overlap_length
            conflicting_overlap_byte_count += conflicting
            if overlap_length == len(payload) and conflicting == 0:
                retransmission_count += 1

        payload_offset = max(0, run["end"] - sequence_offset)
        new_payload = payload[payload_offset:]
        if new_payload:
            available = max_bytes - payload_byte_count
            accepted = new_payload[:available]
            run["payload"].extend(accepted)
            run["end"] += len(accepted)
            payload_byte_count += len(accepted)
            if len(accepted) < len(new_payload):
                truncated = True

    gaps = []
    for previous, following in zip(runs, runs[1:], strict=False):
        missing_bytes = following["start"] - previous["end"]
        if missing_bytes > 0:
            gaps.append(
                {
                    "sequence_start": (anchor + previous["end"]) & _TCP_SEQUENCE_MASK,
                    "sequence_end": (anchor + following["start"]) & _TCP_SEQUENCE_MASK,
                    "missing_bytes": missing_bytes,
                }
            )

    sequence_segments = [
        {
            "sequence_start": (anchor + run["start"]) & _TCP_SEQUENCE_MASK,
            "sequence_end": (anchor + run["end"]) & _TCP_SEQUENCE_MASK,
            "payload": bytes(run["payload"]),
        }
        for run in runs
        if run["payload"]
    ]

    return {
        "segments": sequence_segments,
        "gaps": gaps,
        "payload_bytes": payload_byte_count,
        "overlap_bytes": overlap_byte_count,
        "retransmission_count": retransmission_count,
        "conflicting_overlap_bytes": conflicting_overlap_byte_count,
        "truncated": truncated,
    }


def _import_scapy() -> Any:
    """Lazy import of Scapy to avoid import overhead when unused.

    Returns:
        Scapy module tuple (scapy.all module) or raises ImportError.

    Raises:
        ImportError: If scapy is not installed.
    """
    try:
        import scapy.all as scapy  # type: ignore[import]

        return scapy
    except ImportError as exc:
        raise ImportError("scapy is not installed") from exc


@log_execution(tool_name="pcap_analyze")
@track_metrics("pcap_analyze")
@handle_tool_errors
async def pcap_analyze(
    pcap_path: str,
    max_packets: int = 10000,
) -> ToolResult:
    """Summarize sessions, protocols, and packet statistics from a PCAP file.

    Provides a high-level overview including total packets, unique hosts,
    protocol distribution, top talkers, and session summary — ideal as a
    first-pass triage of a PCAP capture.

    Args:
        pcap_path: Path to a PCAP or PCAPNG capture file.
        max_packets: Maximum number of packets to process (default: 10,000).
            For large captures, use a smaller value or filter first.

    Returns:
        ToolResult with protocol breakdown, top talkers, and session summary.

    Example:
        >>> result = await pcap_analyze("/app/workspace/capture.pcap")
        >>> print(result.data["protocol_distribution"])
    """
    validated = validate_file_path(pcap_path)

    try:
        scapy = _import_scapy()
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "Scapy is not installed",
            hint="Install with: pip install scapy",
        )

    try:
        packets = await asyncio.to_thread(scapy.rdpcap, str(validated), count=max_packets)
    except Exception as exc:
        return failure(
            "PCAP_PARSE_ERROR",
            f"Failed to parse PCAP file: {exc}",
            hint="Ensure the file is a valid PCAP or PCAPNG capture.",
        )

    if len(packets) == 0:
        return success(
            {
                "pcap_path": str(validated),
                "total_packets": 0,
                "message": "PCAP file is empty — no packets found.",
            }
        )

    protocol_counts: dict[str, int] = collections.defaultdict(int)
    src_counts: dict[str, int] = collections.defaultdict(int)
    dst_counts: dict[str, int] = collections.defaultdict(int)
    sessions: set[str] = set()
    total_bytes = 0

    for pkt in packets:
        total_bytes += len(pkt)

        # Protocol detection
        if pkt.haslayer("ICMP"):
            protocol_counts["ICMP"] += 1
        elif pkt.haslayer("TCP"):
            protocol_counts["TCP"] += 1
        elif pkt.haslayer("UDP"):
            protocol_counts["UDP"] += 1
        elif pkt.haslayer("ARP"):
            protocol_counts["ARP"] += 1
        else:
            protocol_counts["Other"] += 1

        # Application layer
        if pkt.haslayer("DNS"):
            protocol_counts["DNS"] += 1
        if pkt.haslayer("HTTP"):
            protocol_counts["HTTP"] += 1
        if pkt.haslayer("TLS") or pkt.haslayer("SSL"):
            protocol_counts["TLS/SSL"] += 1

        # IP endpoints
        if pkt.haslayer("IP"):
            src = pkt["IP"].src
            dst = pkt["IP"].dst
            src_counts[src] += 1
            dst_counts[dst] += 1

            if pkt.haslayer("TCP"):
                dport = pkt["TCP"].dport
                sport = pkt["TCP"].sport
                sessions.add(f"{src}:{sport}->{dst}:{dport}")
            elif pkt.haslayer("UDP"):
                dport = pkt["UDP"].dport
                sport = pkt["UDP"].sport
                sessions.add(f"{src}:{sport}->{dst}:{dport}/UDP")

    top_sources = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_destinations = sorted(dst_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return success(
        {
            "pcap_path": str(validated),
            "total_packets": len(packets),
            "total_bytes": total_bytes,
            "unique_sessions": len(sessions),
            "protocol_distribution": dict(protocol_counts),
            "top_sources": [{"ip": ip, "packets": cnt} for ip, cnt in top_sources],
            "top_destinations": [{"ip": ip, "packets": cnt} for ip, cnt in top_destinations],
            "truncated": len(packets) >= max_packets,
        }
    )


@log_execution(tool_name="pcap_list_connections")
@track_metrics("pcap_list_connections")
@handle_tool_errors
async def pcap_list_connections(
    pcap_path: str,
    protocol: str | None = None,
    max_packets: int = 50000,
) -> ToolResult:
    """List all unique IP/port connections observed in a PCAP capture.

    Args:
        pcap_path: Path to a PCAP or PCAPNG capture file.
        protocol: Filter by protocol ('tcp', 'udp', or None for all).
        max_packets: Maximum packets to process (default: 50,000).

    Returns:
        ToolResult with unique connection tuples (src_ip, src_port, dst_ip, dst_port).

    Example:
        >>> result = await pcap_list_connections("/app/workspace/capture.pcap", protocol="tcp")
        >>> print(result.data["connections"])
    """
    validated = validate_file_path(pcap_path)

    try:
        scapy = _import_scapy()
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "Scapy is not installed",
            hint="Install with: pip install scapy",
        )

    try:
        packets = await asyncio.to_thread(scapy.rdpcap, str(validated), count=max_packets)
    except Exception as exc:
        return failure("PCAP_PARSE_ERROR", f"Failed to parse PCAP: {exc}")

    connections: set[tuple[str, ...]] = set()

    for pkt in packets:
        if not pkt.haslayer("IP"):
            continue

        src_ip = pkt["IP"].src
        dst_ip = pkt["IP"].dst

        if pkt.haslayer("TCP") and (protocol is None or protocol.lower() == "tcp"):
            connections.add((src_ip, str(pkt["TCP"].sport), dst_ip, str(pkt["TCP"].dport), "TCP"))
        elif pkt.haslayer("UDP") and (protocol is None or protocol.lower() == "udp"):
            connections.add((src_ip, str(pkt["UDP"].sport), dst_ip, str(pkt["UDP"].dport), "UDP"))

    conn_list = [
        {
            "src_ip": c[0],
            "src_port": int(c[1]),
            "dst_ip": c[2],
            "dst_port": int(c[3]),
            "protocol": c[4],
            "suspicious_port": int(c[3]) in _SUSPICIOUS_PORTS or int(c[1]) in _SUSPICIOUS_PORTS,
        }
        for c in sorted(connections)
    ]

    suspicious = [c for c in conn_list if c["suspicious_port"]]

    return success(
        {
            "pcap_path": str(validated),
            "connections": conn_list[:2000],
            "total_connections": len(conn_list),
            "suspicious_connections": suspicious[:100],
            "suspicious_count": len(suspicious),
            "protocol_filter": protocol,
        }
    )


@log_execution(tool_name="pcap_extract_dns")
@track_metrics("pcap_extract_dns")
@handle_tool_errors
async def pcap_extract_dns(
    pcap_path: str,
    include_responses: bool = True,
    max_packets: int = 50000,
) -> ToolResult:
    """Extract DNS queries and responses from a PCAP capture.

    Useful for identifying C2 domain lookups, DGA patterns, DNS tunneling,
    and suspicious resolution activity.

    Args:
        pcap_path: Path to a PCAP or PCAPNG capture file.
        include_responses: If True, also extract DNS response records (A, AAAA, MX, TXT).
        max_packets: Maximum packets to process (default: 50,000).

    Returns:
        ToolResult with DNS query/response pairs, unique domains, and anomaly flags.

    Example:
        >>> result = await pcap_extract_dns("/app/workspace/capture.pcap")
        >>> print(result.data["unique_domains"])
    """
    validated = validate_file_path(pcap_path)

    try:
        scapy = _import_scapy()
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "Scapy is not installed",
            hint="Install with: pip install scapy",
        )

    try:
        packets = await asyncio.to_thread(scapy.rdpcap, str(validated), count=max_packets)
    except Exception as exc:
        return failure("PCAP_PARSE_ERROR", f"Failed to parse PCAP: {exc}")

    queries: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    unique_domains: set[str] = set()

    # DGA detection heuristics: high entropy, long random-looking names
    dga_pattern = re.compile(r"^[a-z0-9]{10,}\.(com|net|org|io|cc|ru|cn)$", re.IGNORECASE)

    for pkt in packets:
        if not pkt.haslayer("DNS"):
            continue

        dns = pkt["DNS"]

        # Extract queries (qr=0). Scapy exposes parsed questions as a list;
        # some callers and older Scapy versions expose a linked payload chain.
        if dns.qr == 0:
            try:
                question_count = max(0, int(dns.qdcount))
                question_section = dns.qd
                if isinstance(question_section, (list, tuple)):
                    question_records = question_section[:question_count]
                else:
                    question_records = []
                    question = question_section
                    for _ in range(question_count):
                        if question is None or getattr(question, "name", None) == "NoPayload":
                            break
                        question_records.append(question)
                        question = getattr(question, "payload", None)

                for question in question_records:
                    name = question.qname.decode(errors="replace").rstrip(".")
                    qtype = question.qtype
                    unique_domains.add(name)
                    queries.append(
                        {
                            "domain": name,
                            "qtype": qtype,
                            "possible_dga": bool(dga_pattern.match(name)),
                            "src_ip": pkt["IP"].src if pkt.haslayer("IP") else None,
                        }
                    )
            except Exception as exc:
                logger.debug("DNS query parse error: %s", exc)

        # Extract responses (qr=1)
        if include_responses and dns.qr == 1 and dns.ancount > 0:
            try:
                an = dns.an
                while an:
                    rtype = getattr(an, "type", None)
                    rdata = None
                    if rtype == 1:  # A record
                        rdata = str(getattr(an, "rdata", ""))
                    elif rtype == 28:  # AAAA record
                        rdata = str(getattr(an, "rdata", ""))
                    elif rtype == 16:  # TXT record
                        rdata = str(getattr(an, "rdata", ""))

                    if rdata:
                        rrname = getattr(an, "rrname", b"")
                        if isinstance(rrname, bytes):
                            rrname = rrname.decode(errors="replace").rstrip(".")
                        responses.append({"domain": rrname, "type": rtype, "rdata": rdata})

                    an = getattr(an, "payload", None)
                    if not an or an.name == "NoPayload":
                        break
            except Exception as exc:
                logger.debug("DNS response parse error: %s", exc)

    possible_dga = [q for q in queries if q.get("possible_dga")]

    return success(
        {
            "pcap_path": str(validated),
            "total_queries": len(queries),
            "total_responses": len(responses),
            "unique_domains": sorted(unique_domains)[:500],
            "unique_domain_count": len(unique_domains),
            "queries": queries[:500],
            "responses": responses[:500] if include_responses else [],
            "possible_dga_domains": possible_dga[:50],
            "dga_count": len(possible_dga),
        }
    )


@log_execution(tool_name="pcap_extract_c2")
@track_metrics("pcap_extract_c2")
@handle_tool_errors
async def pcap_extract_c2(
    pcap_path: str,
    beacon_threshold_sec: int = 60,
    max_packets: int = 100000,
) -> ToolResult:
    """Detect potential C2 traffic patterns in a PCAP capture.

    Detects:
    - Beaconing behavior (periodic connections to same host)
    - Connections to known suspicious ports
    - Unusually long/persistent connections
    - DNS-over-HTTPS (DoH) patterns

    Args:
        pcap_path: Path to a PCAP or PCAPNG capture file.
        beacon_threshold_sec: Maximum jitter window (seconds) to consider as beaconing.
        max_packets: Maximum packets to process (default: 100,000).

    Returns:
        ToolResult with C2 indicators, beaconing hosts, and risk assessment.

    Example:
        >>> result = await pcap_extract_c2("/app/workspace/malware_traffic.pcap")
        >>> print(result.data["suspected_c2_hosts"])
    """
    validated = validate_file_path(pcap_path)

    if not isinstance(beacon_threshold_sec, int) or isinstance(beacon_threshold_sec, bool):
        raise ValidationError("beacon_threshold_sec must be an integer")
    if beacon_threshold_sec <= 0:
        raise ValidationError("beacon_threshold_sec must be greater than 0")
    if beacon_threshold_sec > 3600:
        raise ValidationError("beacon_threshold_sec cannot exceed 3600 seconds")

    try:
        scapy = _import_scapy()
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "Scapy is not installed",
            hint="Install with: pip install scapy",
        )

    try:
        packets = await asyncio.to_thread(scapy.rdpcap, str(validated), count=max_packets)
    except Exception as exc:
        return failure("PCAP_PARSE_ERROR", f"Failed to parse PCAP: {exc}")

    beacon_criteria = {
        "beacon_threshold_sec": beacon_threshold_sec,
        "max_jitter_sec": beacon_threshold_sec,
        "max_relative_jitter": 0.3,
        "max_interval_sec": 3600,
    }

    if len(packets) == 0:
        return success(
            {
                "pcap_path": str(validated),
                "beacon_threshold_sec": beacon_threshold_sec,
                "beacon_criteria": beacon_criteria,
                "message": "Empty PCAP — no C2 indicators.",
            }
        )

    # Track timestamps per destination (host, port) pair
    dst_timestamps: dict[tuple[str, int], list[float]] = collections.defaultdict(list)
    suspicious_port_hits: list[dict[str, Any]] = []

    for pkt in packets:
        if not pkt.haslayer("IP"):
            continue

        ts = float(pkt.time)
        dst_ip = pkt["IP"].dst

        if pkt.haslayer("TCP"):
            dport = pkt["TCP"].dport
            dst_timestamps[(dst_ip, dport)].append(ts)

            if dport in _SUSPICIOUS_PORTS:
                suspicious_port_hits.append(
                    {
                        "dst_ip": dst_ip,
                        "dport": dport,
                        "src_ip": pkt["IP"].src,
                        "time": ts,
                    }
                )
        elif pkt.haslayer("UDP"):
            dport = pkt["UDP"].dport
            dst_timestamps[(dst_ip, dport)].append(ts)

    # Detect beaconing: hosts with regular connection intervals
    beaconing_hosts: list[dict[str, Any]] = []
    for (dst_ip, dport), timestamps in dst_timestamps.items():
        if len(timestamps) < _BEACON_MIN_PACKETS:
            continue

        timestamps.sort()
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if not intervals:
            continue

        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance**0.5

        # Low std deviation relative to mean = highly periodic = likely beacon
        # Jitter std_dev must also satisfy beacon_threshold_sec
        if (
            avg_interval > 0
            and std_dev <= beacon_threshold_sec
            and std_dev / avg_interval < 0.3
            and avg_interval <= 3600
        ):
            beaconing_hosts.append(
                {
                    "dst_ip": dst_ip,
                    "dst_port": dport,
                    "packet_count": len(timestamps),
                    "avg_interval_sec": round(avg_interval, 2),
                    "std_dev_sec": round(std_dev, 2),
                    "periodicity_score": round(1.0 - (std_dev / avg_interval), 3),
                    "suspicious_port": dport in _SUSPICIOUS_PORTS,
                    "beacon_threshold_sec": beacon_threshold_sec,
                }
            )

    beaconing_hosts.sort(key=lambda x: x["periodicity_score"], reverse=True)

    c2_indicators = len(beaconing_hosts) + len(suspicious_port_hits)
    risk = "CRITICAL" if c2_indicators > 5 else "HIGH" if c2_indicators > 0 else "LOW"

    return success(
        {
            "pcap_path": str(validated),
            "beacon_threshold_sec": beacon_threshold_sec,
            "beacon_criteria": beacon_criteria,
            "suspected_c2_hosts": beaconing_hosts[:20],
            "beaconing_count": len(beaconing_hosts),
            "suspicious_port_hits": suspicious_port_hits[:50],
            "suspicious_port_count": len(suspicious_port_hits),
            "risk_level": risk,
            "c2_indicator_count": c2_indicators,
        }
    )


@log_execution(tool_name="pcap_reconstruct_stream")
@track_metrics("pcap_reconstruct_stream")
@handle_tool_errors
async def pcap_reconstruct_stream(
    pcap_path: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    max_packets: int = 10000,
    max_bytes: int = 1024 * 1024,  # 1 MB
    src_port: int | None = None,
    output_mode: str = "hex",
    max_bytes_c2s: int | None = None,
    max_bytes_s2c: int | None = None,
    packet_scope: str = "file",
    output_dir: str = "streams",
) -> ToolResult:
    """Reconstruct TCP stream payload from a PCAP capture.

    Selects one TCP flow using its four endpoint values and reassembles each
    direction independently by TCP sequence number. Gaps remain explicit, and
    retransmissions or conflicting overlaps are counted rather than duplicated.

    Args:
        pcap_path: Path to a PCAP or PCAPNG capture file.
        src_ip: Source IP address of the stream.
        dst_ip: Destination IP address of the stream.
        dst_port: Destination TCP port of the stream.
        src_port: Optional source TCP port. If omitted, a source port is inferred
            only when exactly one flow matches the IP addresses and destination port.
        max_packets: Maximum packets to process (default: 10,000). With
            ``packet_scope="file"`` this counts packets from the start of the
            file; with ``packet_scope="flow"`` it counts only packets of the
            selected flow.
        max_bytes: Maximum unique payload bytes to reconstruct per direction
            (default: 1 MB).
        output_mode: ``"hex"`` (default) returns up to 4 KB of hex and ASCII per
            direction. ``"summary"`` returns sizes, SHA-256 and a 256-byte
            printable preview per direction instead of hex. ``"file"`` also
            writes each direction's reassembled bytes into ``output_dir`` and
            returns the file paths, so large streams can be analysed with other
            tools without passing the bytes through the MCP response.
        max_bytes_c2s: Optional byte limit for the source-to-destination
            direction, overriding ``max_bytes``.
        max_bytes_s2c: Optional byte limit for the destination-to-source
            direction, overriding ``max_bytes``.
        packet_scope: ``"file"`` (default) or ``"flow"``. See ``max_packets``.
        output_dir: Directory for ``output_mode="file"``, relative to the
            workspace or absolute inside it (default: ``streams``).

    Returns:
        ToolResult with separate source-to-destination and reverse streams,
        including sequence ranges, explicit gaps, duplicate retransmission counts,
        and conflicting overlap counts. The top-level hex and ASCII fields show
        source-to-destination bytes; reverse bytes are in ``reverse_stream``.
        Top-level hex omits missing gap bytes, which are listed in
        ``forward_stream.gaps``. In ``file`` mode each direction also carries a
        ``file`` entry with ``path``, ``bytes``, ``sha256`` and ``gaps`` (file
        offsets where captured data is missing; no bytes are fabricated).

    Example:
        >>> result = await pcap_reconstruct_stream(
        ...     "/app/workspace/capture.pcap",
        ...     src_ip="192.168.1.5",
        ...     dst_ip="10.0.0.1",
        ...     dst_port=4444,
        ...     src_port=52314,
        ... )
    """
    if src_port is not None and (
        isinstance(src_port, bool) or not isinstance(src_port, int) or not 0 <= src_port <= 65535
    ):
        return failure("INVALID_PARAMETER", "src_port must be an integer between 0 and 65535")
    if output_mode not in _STREAM_OUTPUT_MODES:
        return failure(
            "INVALID_PARAMETER",
            f"output_mode must be one of: {', '.join(sorted(_STREAM_OUTPUT_MODES))}",
        )
    if packet_scope not in ("file", "flow"):
        return failure("INVALID_PARAMETER", "packet_scope must be 'file' or 'flow'")
    for name, value in (
        ("max_bytes_c2s", max_bytes_c2s),
        ("max_bytes_s2c", max_bytes_s2c),
    ):
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 0
        ):
            return failure("INVALID_PARAMETER", f"{name} must be a non-negative integer")

    validated = validate_file_path(pcap_path)

    stream_dir: Path | None = None
    if output_mode == "file":
        workspace = get_workspace_config().workspace.resolve()
        requested = Path(output_dir)
        stream_dir = (requested if requested.is_absolute() else workspace / requested).resolve()
        if not stream_dir.is_relative_to(workspace):
            return failure(
                "PATH_TRAVERSAL_DETECTED",
                f"output_dir '{output_dir}' must reside within the workspace directory",
            )

    try:
        scapy = _import_scapy()
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "Scapy is not installed",
            hint="Install with: pip install scapy",
        )

    try:
        if packet_scope == "flow":
            packets = await asyncio.to_thread(scapy.rdpcap, str(validated))
        else:
            packets = await asyncio.to_thread(scapy.rdpcap, str(validated), count=max_packets)
    except Exception as exc:
        return failure("PCAP_PARSE_ERROR", f"Failed to parse PCAP: {exc}")

    flow_packets: list[tuple[Any, str, str, int, int]] = []
    candidate_source_ports: set[int] = set()

    for pkt in packets:
        if not (pkt.haslayer("IP") and pkt.haslayer("TCP")):
            continue

        pkt_src = pkt["IP"].src
        pkt_dst = pkt["IP"].dst
        tcp = pkt["TCP"]
        pkt_sport = int(tcp.sport)
        pkt_dport = int(tcp.dport)

        is_forward_endpoint = pkt_src == src_ip and pkt_dst == dst_ip and pkt_dport == dst_port
        is_reverse_endpoint = pkt_src == dst_ip and pkt_dst == src_ip and pkt_sport == dst_port

        if is_forward_endpoint:
            candidate_source_ports.add(pkt_sport)
        if is_reverse_endpoint:
            candidate_source_ports.add(pkt_dport)
        if is_forward_endpoint or is_reverse_endpoint:
            flow_packets.append((pkt, pkt_src, pkt_dst, pkt_sport, pkt_dport))

    flow_packets_truncated = False

    if src_port is None and len(candidate_source_ports) > 1:
        return failure(
            "AMBIGUOUS_TCP_FLOW",
            "Multiple TCP flows match these IP addresses and destination port; specify src_port.",
            candidate_source_ports=sorted(candidate_source_ports),
        )

    selected_src_port = src_port
    if selected_src_port is None and candidate_source_ports:
        selected_src_port = next(iter(candidate_source_ports))

    forward_segments: list[tuple[int, bytes]] = []
    reverse_segments: list[tuple[int, bytes]] = []
    selected_packet_count = 0
    for pkt, pkt_src, pkt_dst, pkt_sport, pkt_dport in flow_packets:
        is_forward = (
            selected_src_port is not None
            and pkt_src == src_ip
            and pkt_dst == dst_ip
            and pkt_sport == selected_src_port
            and pkt_dport == dst_port
        )
        is_reverse = (
            selected_src_port is not None
            and pkt_src == dst_ip
            and pkt_dst == src_ip
            and pkt_sport == dst_port
            and pkt_dport == selected_src_port
        )
        if not (is_forward or is_reverse):
            continue
        if packet_scope == "flow":
            # Count only packets of the selected flow, so max_packets bounds this
            # flow rather than the whole file.
            if selected_packet_count >= max_packets:
                flow_packets_truncated = True
                break
            selected_packet_count += 1
        if not pkt.haslayer("Raw"):
            continue

        tcp = pkt["TCP"]
        try:
            sequence = int(tcp.seq)
            flags = int(tcp.flags)
        except (AttributeError, TypeError, ValueError) as exc:
            logger.debug("TCP sequence parse error: %s", exc)
            continue
        if flags & 0x02:  # SYN consumes one sequence number before its payload.
            sequence += 1

        payload = bytes(pkt["Raw"].load)
        if is_forward:
            forward_segments.append((sequence, payload))
        else:
            reverse_segments.append((sequence, payload))

    forward_data = _reassemble_tcp_payloads(
        forward_segments, max_bytes if max_bytes_c2s is None else max_bytes_c2s
    )
    reverse_data = _reassemble_tcp_payloads(
        reverse_segments, max_bytes if max_bytes_s2c is None else max_bytes_s2c
    )
    include_hex = output_mode == "hex"

    def describe_direction(
        direction: str,
        direction_src_ip: str,
        direction_src_port: int | None,
        direction_dst_ip: str,
        direction_dst_port: int | None,
        segments: list[tuple[int, bytes]],
        assembled: dict[str, Any],
    ) -> dict[str, Any]:
        described_segments = []
        display_budget = 4096 if include_hex else 0
        for segment in assembled["segments"][:1000]:
            payload = segment["payload"]
            display_payload = payload[:display_budget]
            display_budget -= len(display_payload)
            described = {
                "sequence_start": segment["sequence_start"],
                "sequence_end": segment["sequence_end"],
                "payload_bytes": len(payload),
            }
            if include_hex:
                described.update(
                    {
                        "hex_dump": display_payload.hex(),
                        "printable_ascii": "".join(
                            chr(byte) if 32 <= byte < 127 else "." for byte in display_payload
                        ),
                        "display_truncated": len(display_payload) < len(payload),
                    }
                )
            described_segments.append(described)
        omitted_segments = max(0, len(assembled["segments"]) - len(described_segments))
        omitted_gaps = max(0, len(assembled["gaps"]) - 1000)
        extra: dict[str, Any] = {}
        if not include_hex:
            joined, file_gaps = _join_runs(assembled)
            extra["sha256"] = hashlib.sha256(joined).hexdigest()
            extra["preview_printable"] = "".join(
                chr(byte) if 32 <= byte < 127 else "." for byte in joined[:256]
            )
            if stream_dir is not None and joined:
                endpoint_label = re.sub(
                    r"[^A-Za-z0-9._-]",
                    "_",
                    f"{direction_src_ip}-{direction_src_port}_{direction_dst_ip}-{direction_dst_port}",
                )
                stream_dir.mkdir(parents=True, exist_ok=True)
                file_path = stream_dir / f"{Path(validated).stem}_{endpoint_label}_{direction}.bin"
                file_path.write_bytes(joined)
                extra["file"] = {
                    "path": str(file_path),
                    "bytes": len(joined),
                    "sha256": extra["sha256"],
                    "gaps": file_gaps,
                }
        return {
            **extra,
            "direction": direction,
            "src_ip": direction_src_ip,
            "src_port": direction_src_port,
            "dst_ip": direction_dst_ip,
            "dst_port": direction_dst_port,
            "matching_packets": len(segments),
            "payload_bytes": assembled["payload_bytes"],
            "segments": described_segments,
            "segments_omitted": omitted_segments,
            "gaps": assembled["gaps"][:1000],
            "gaps_omitted": omitted_gaps,
            "overlap_bytes": assembled["overlap_bytes"],
            "retransmission_count": assembled["retransmission_count"],
            "conflicting_overlap_bytes": assembled["conflicting_overlap_bytes"],
            "truncated": assembled["truncated"],
        }

    forward_stream = describe_direction(
        "src_to_dst",
        src_ip,
        selected_src_port,
        dst_ip,
        dst_port,
        forward_segments,
        forward_data,
    )
    reverse_stream = describe_direction(
        "dst_to_src",
        dst_ip,
        dst_port,
        src_ip,
        selected_src_port,
        reverse_segments,
        reverse_data,
    )

    forward_payload = b"".join(segment["payload"] for segment in forward_data["segments"])
    printable_parts = []
    for index, segment in enumerate(forward_data["segments"]):
        if index:
            gap = forward_data["gaps"][index - 1]
            printable_parts.append(f"<GAP:{gap['missing_bytes']} bytes>")
        printable_parts.append(
            "".join(chr(byte) if 32 <= byte < 127 else "." for byte in segment["payload"])
        )
    printable = "".join(printable_parts)

    flow = {
        "src_ip": src_ip,
        "src_port": selected_src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
    }
    total_payload_bytes = forward_data["payload_bytes"] + reverse_data["payload_bytes"]
    total_packet_count = len(forward_segments) + len(reverse_segments)

    return success(
        {
            "pcap_path": str(validated),
            "src_ip": src_ip,
            "src_port": selected_src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "flow": flow,
            "matching_packets": total_packet_count,
            "payload_bytes": total_payload_bytes,
            "output_mode": output_mode,
            "packet_scope": packet_scope,
            "hex_dump": forward_payload[:4096].hex() if include_hex else "",
            "printable_ascii": printable[: 4096 if include_hex else 256],
            "forward_stream": forward_stream,
            "reverse_stream": reverse_stream,
            "truncated": forward_data["truncated"]
            or reverse_data["truncated"]
            or flow_packets_truncated,
            **(
                {
                    "message": "No payload found for the specified TCP flow. Check the IP and port values."
                }
                if total_payload_bytes == 0
                else {}
            ),
        }
    )


_HTTP_SUMMARY_MAX_TRANSACTIONS = 5000


def _packet_endpoints(pkt: Any) -> tuple[str, str] | None:
    """Return (src, dst) addresses for IPv4 or IPv6 packets, else None."""
    if pkt.haslayer("IP"):
        layer = pkt["IP"]
    elif pkt.haslayer("IPv6"):
        layer = pkt["IPv6"]
    else:
        return None
    return str(layer.src), str(layer.dst)


def _join_runs(assembled: dict[str, Any]) -> tuple[bytes, list[dict[str, int]]]:
    """Concatenate reassembled runs and report where capture gaps fall.

    No bytes are fabricated for gaps; each gap is reported with the offset in
    the joined output where the missing data would have started.
    """
    output = bytearray()
    gaps: list[dict[str, int]] = []
    for index, segment in enumerate(assembled["segments"]):
        if index and index - 1 < len(assembled["gaps"]):
            gaps.append(
                {
                    "file_offset": len(output),
                    "missing_bytes": assembled["gaps"][index - 1]["missing_bytes"],
                }
            )
        output.extend(segment["payload"])
    return bytes(output), gaps


def _utc_iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.datetime.fromtimestamp(float(timestamp), datetime.timezone.utc).isoformat()


def _summarize_http_flows(
    packets: Any,
    ports: set[int] | None,
    watch_fields: list[str],
    max_bytes_per_direction: int,
    inspection_window: int,
    max_transactions: int,
    max_field_runs: int,
) -> dict[str, Any]:
    flows: dict[tuple, dict[str, Any]] = {}
    for pkt in packets:
        if not pkt.haslayer("TCP"):
            continue
        endpoints = _packet_endpoints(pkt)
        if endpoints is None:
            continue
        src, dst = endpoints
        tcp = pkt["TCP"]
        try:
            sport, dport = int(tcp.sport), int(tcp.dport)
            sequence, tcp_flags = int(tcp.seq), int(tcp.flags)
        except (AttributeError, TypeError, ValueError):
            continue
        a, b = (src, sport), (dst, dport)
        key = (a, b) if a <= b else (b, a)
        flow = flows.setdefault(
            key,
            {
                "segments": {a: [], b: []},
                "syn_from": None,
                "rst": False,
                "first": None,
                "last": None,
            },
        )
        flow["segments"].setdefault(a, [])
        timestamp = getattr(pkt, "time", None)
        if timestamp is not None:
            timestamp = float(timestamp)
            flow["first"] = timestamp if flow["first"] is None else min(flow["first"], timestamp)
            flow["last"] = timestamp if flow["last"] is None else max(flow["last"], timestamp)
        if tcp_flags & 0x02 and not tcp_flags & 0x10 and flow["syn_from"] is None:
            flow["syn_from"] = a
        if tcp_flags & 0x04:
            flow["rst"] = True
        if tcp_flags & 0x02:
            sequence += 1
        if pkt.haslayer("Raw"):
            flow["segments"][a].append((sequence, bytes(pkt["Raw"].load)))

    transactions: list[dict[str, Any]] = []
    totals: collections.Counter[str] = collections.Counter()
    for key, flow in sorted(flows.items(), key=lambda item: item[1]["first"] or 0.0):
        totals["tcp_flows"] += 1
        assembled = {
            endpoint: _reassemble_tcp_payloads(segments, max_bytes_per_direction)
            for endpoint, segments in flow["segments"].items()
        }
        joined = {endpoint: _join_runs(data) for endpoint, data in assembled.items()}

        client = flow["syn_from"]
        if client is None or not _http_summary.looks_like_request(joined[client][0]):
            client = next(
                (ep for ep, (data, _) in joined.items() if _http_summary.looks_like_request(data)),
                None,
            )
        if client is None:
            totals["non_http_flows"] += 1
            continue
        server = key[1] if key[0] == client else key[0]
        if ports and server[1] not in ports:
            totals["filtered_flows"] += 1
            continue
        totals["http_flows"] += 1

        client_data, client_gaps = joined[client]
        server_data, server_gaps = joined.get(server, (b"", []))
        requests = _http_summary.parse_http_messages(client_data, "request")
        methods = [message["start_line"].split(" ", 1)[0] for message in requests]
        responses = (
            _http_summary.parse_http_messages(server_data, "response", methods)
            if _http_summary.looks_like_response(server_data)
            else []
        )

        for index, request_message in enumerate(requests):
            totals["transactions"] += 1
            if len(transactions) >= max_transactions:
                totals["transactions_omitted"] += 1
                continue
            request = _http_summary.describe_request(
                client_data, request_message, watch_fields, max_field_runs
            )
            response = (
                _http_summary.describe_response(responses[index])
                if index < len(responses)
                else None
            )
            flags: list[str] = []
            if response is None:
                flags.append("no_response")
                totals["no_response"] += 1
            elif response["set_cookie_anomalies"]:
                flags.append("anomalous_set_cookie")
                totals["anomalous_set_cookie"] += 1
            if flow["rst"]:
                flags.append("connection_reset")
            if not request["complete"]:
                flags.append("request_incomplete_in_capture")
            if client_gaps or server_gaps:
                flags.append("capture_gaps")
            deep_fields = [
                name
                for name, offset in request.get("multipart", {})
                .get("watched_field_offsets", {})
                .items()
                if offset is not None and offset >= inspection_window
            ]
            if deep_fields:
                flags.append("watched_field_beyond_inspection_window")
                request["fields_beyond_inspection_window"] = deep_fields

            transactions.append(
                {
                    "client": f"{client[0]}:{client[1]}",
                    "server": f"{server[0]}:{server[1]}",
                    "first_seen": _utc_iso(flow["first"]),
                    "last_seen": _utc_iso(flow["last"]),
                    "flow_duration_ms": (
                        round((flow["last"] - flow["first"]) * 1000, 1)
                        if flow["first"] is not None and flow["last"] is not None
                        else None
                    ),
                    "request": request,
                    "response": response,
                    "flags": flags,
                }
            )

    return {"transactions": transactions, "totals": dict(totals)}


@log_execution(tool_name="pcap_http_summary")
@track_metrics("pcap_http_summary")
@handle_tool_errors
async def pcap_http_summary(
    pcap_path: str,
    max_packets: int = 200000,
    ports: list[int] | None = None,
    watch_fields: list[str] | None = None,
    inspection_window: int = 100 * 1024,
    max_bytes_per_direction: int = 64 * 1024 * 1024,
    max_transactions: int = 500,
    max_field_runs: int = 20,
) -> ToolResult:
    """Summarize HTTP/1.x requests and responses in a PCAP without returning payload bytes.

    Reassembles every TCP flow, splits it into HTTP transactions and reports the
    shape of each one: request line, selected headers, body sizes, multipart
    field structure, response status and headers. Field values and bodies are
    never returned, so captures with very large requests stay cheap to triage.

    Each transaction carries flags for common investigation signals:
    ``no_response`` (the server sent nothing back, for example a crashed
    worker), ``anomalous_set_cookie`` (a Set-Cookie value that decodes to
    binary or heavily percent-encoded data, a sign of reflected memory),
    ``connection_reset``, ``request_incomplete_in_capture``, ``capture_gaps``
    and ``watched_field_beyond_inspection_window``.

    Args:
        pcap_path: Path to a PCAP or PCAPNG capture file.
        max_packets: Maximum packets to read from the file (default: 200,000).
        ports: Only report flows whose server port is in this list. Default: all ports.
        watch_fields: Multipart form-field names whose byte offset in the body
            should be reported, for example ``["PHP_SESSION_UPLOAD_PROGRESS"]``.
        inspection_window: Body offset in bytes beyond which a watched field is
            flagged (default: 102,400, Suricata's default request-body-limit).
        max_bytes_per_direction: Maximum bytes reassembled per flow direction
            (default: 64 MB). Larger bodies are measured as incomplete.
        max_transactions: Maximum transactions returned (default: 500, max 5,000).
        max_field_runs: Maximum run-length entries per multipart summary (default: 20).

    Returns:
        ToolResult with ``transactions`` (one entry per HTTP request, paired with
        its response when present) and ``totals`` (flow and flag counts).

    Example:
        >>> result = await pcap_http_summary(
        ...     "/app/workspace/capture.pcap",
        ...     watch_fields=["PHP_SESSION_UPLOAD_PROGRESS"],
        ... )
    """
    for name, value, minimum in (
        ("max_packets", max_packets, 1),
        ("inspection_window", inspection_window, 0),
        ("max_bytes_per_direction", max_bytes_per_direction, 1),
        ("max_transactions", max_transactions, 1),
        ("max_field_runs", max_field_runs, 1),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            return failure("INVALID_PARAMETER", f"{name} must be an integer >= {minimum}")
    if max_transactions > _HTTP_SUMMARY_MAX_TRANSACTIONS:
        return failure(
            "INVALID_PARAMETER",
            f"max_transactions must not exceed {_HTTP_SUMMARY_MAX_TRANSACTIONS}",
        )
    port_filter: set[int] | None = None
    if ports:
        if any(
            isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535
            for port in ports
        ):
            return failure("INVALID_PARAMETER", "ports must contain integers between 0 and 65535")
        port_filter = set(ports)
    fields = [str(field) for field in (watch_fields or [])]

    validated = validate_file_path(pcap_path)

    try:
        scapy = _import_scapy()
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "Scapy is not installed",
            hint="Install with: pip install scapy",
        )

    try:
        packets = await asyncio.to_thread(scapy.rdpcap, str(validated), count=max_packets)
    except Exception as exc:
        return failure("PCAP_PARSE_ERROR", f"Failed to parse PCAP: {exc}")

    summary = await asyncio.to_thread(
        _summarize_http_flows,
        packets,
        port_filter,
        fields,
        max_bytes_per_direction,
        inspection_window,
        max_transactions,
        max_field_runs,
    )

    return success(
        {
            "pcap_path": str(validated),
            "packets_read": len(packets),
            "packets_truncated": len(packets) >= max_packets,
            "watch_fields": fields,
            "inspection_window": inspection_window,
            "totals": summary["totals"],
            "transactions": summary["transactions"],
        }
    )
