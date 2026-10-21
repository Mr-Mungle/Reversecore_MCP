"""Pure helpers for summarizing HTTP/1.x traffic reassembled from a PCAP.

These functions never return payload bytes. They describe the *shape* of each
HTTP message (request line, selected headers, body size, multipart structure)
so that large captures can be triaged without streaming megabytes of hex back
to the MCP client.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote_to_bytes

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
    b"PROPFIND ",
)

REQUEST_HEADERS = (
    "host",
    "user-agent",
    "content-type",
    "content-length",
    "transfer-encoding",
    "cookie",
    "referer",
    "x-forwarded-for",
    "expect",
    "connection",
)

RESPONSE_HEADERS = (
    "server",
    "x-powered-by",
    "content-type",
    "content-length",
    "transfer-encoding",
    "set-cookie",
    "location",
    "connection",
)

MAX_HEADER_VALUE_CHARS = 256
MAX_HEADER_BLOCK_BYTES = 64 * 1024
_BOUNDARY_RE = re.compile(rb"boundary=\"?([^\";\r\n]+)\"?", re.IGNORECASE)
_NAME_RE = re.compile(rb'\bname="([^"]*)"', re.IGNORECASE)
_FILENAME_RE = re.compile(rb'\bfilename="([^"]*)"', re.IGNORECASE)
_PERCENT_ESCAPE_RE = re.compile(rb"%[0-9A-Fa-f]{2}")


def looks_like_request(data: bytes) -> bool:
    """Return True when a byte stream starts with an HTTP/1.x request line."""
    return data.startswith(HTTP_METHODS)


def looks_like_response(data: bytes) -> bool:
    """Return True when a byte stream starts with an HTTP/1.x status line."""
    return data.startswith(b"HTTP/")


def _decode(value: bytes) -> str:
    return value.decode("latin-1")


def _truncate(text: str, limit: int = MAX_HEADER_VALUE_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + f"...(+{len(text) - limit} chars)"


def _parse_header_block(block: bytes) -> tuple[str, list[tuple[str, bytes]]]:
    lines = block.split(b"\r\n")
    start_line = _decode(lines[0])
    headers: list[tuple[str, bytes]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[:1] in (b" ", b"\t") and headers:
            previous_name, previous_value = headers[-1]
            headers[-1] = (previous_name, previous_value + b" " + line.strip())
            continue
        raw_name, sep, raw_value = line.partition(b":")
        if not sep:
            continue
        headers.append((_decode(raw_name.strip()).lower(), raw_value.strip()))
    return start_line, headers


def _header_value(headers: list[tuple[str, bytes]], name: str) -> bytes | None:
    for header_name, value in headers:
        if header_name == name:
            return value
    return None


def _select_headers(headers: list[tuple[str, bytes]], wanted: tuple[str, ...]) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    for header_name, value in headers:
        if header_name not in wanted:
            continue
        text = _truncate(_decode(value))
        if header_name in selected:
            existing = selected[header_name]
            selected[header_name] = (
                existing + [text] if isinstance(existing, list) else [existing, text]
            )
        else:
            selected[header_name] = text
    return selected


def _measure_chunked(data: bytes, start: int) -> tuple[int, int, bool]:
    """Walk a chunked body without copying it.

    Returns (decoded_body_bytes, end_offset, complete).
    """
    offset = start
    decoded = 0
    while True:
        line_end = data.find(b"\r\n", offset)
        if line_end < 0:
            return decoded, len(data), False
        size_text = data[offset:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return decoded, len(data), False
        offset = line_end + 2
        if size == 0:
            trailer_end = data.find(b"\r\n\r\n", offset - 2)
            if trailer_end < 0:
                return decoded, len(data), False
            return decoded, trailer_end + 4, True
        if offset + size + 2 > len(data):
            decoded += max(0, len(data) - offset)
            return decoded, len(data), False
        decoded += size
        offset += size + 2


def parse_http_messages(
    data: bytes, kind: str, request_methods: list[str] | None = None
) -> list[dict[str, Any]]:
    """Split a reassembled HTTP/1.x stream into message descriptors.

    Args:
        data: Reassembled bytes for one direction of a TCP flow.
        kind: ``"request"`` or ``"response"``.
        request_methods: For responses, the methods of the matching requests so
            that bodies of HEAD responses are not over-read.

    Returns:
        A list of dicts with ``start_line``, ``headers`` (raw tuples),
        ``header_bytes``, ``body_offset``, ``body_bytes``, ``declared_length``,
        ``chunked`` and ``complete`` keys. ``body_offset`` is relative to ``data``.
    """
    messages: list[dict[str, Any]] = []
    offset = 0
    index = 0
    while offset < len(data):
        header_end = data.find(b"\r\n\r\n", offset, offset + MAX_HEADER_BLOCK_BYTES)
        if header_end < 0:
            messages.append(
                {
                    "start_line": _decode(data[offset : offset + 120].split(b"\r\n", 1)[0]),
                    "headers": [],
                    "header_bytes": len(data) - offset,
                    "body_offset": len(data),
                    "body_bytes": 0,
                    "declared_length": None,
                    "chunked": False,
                    "complete": False,
                }
            )
            break

        start_line, headers = _parse_header_block(data[offset:header_end])
        body_offset = header_end + 4
        transfer_encoding = (_header_value(headers, "transfer-encoding") or b"").lower()
        length_value = _header_value(headers, "content-length")
        declared_length: int | None = None
        if length_value is not None:
            try:
                declared_length = int(length_value.strip())
            except ValueError:
                declared_length = None

        chunked = b"chunked" in transfer_encoding
        status_code = None
        if kind == "response":
            parts = start_line.split(" ", 2)
            if len(parts) > 1 and parts[1].isdigit():
                status_code = int(parts[1])

        no_body = kind == "response" and (
            (status_code is not None and (status_code < 200 or status_code in (204, 304)))
            or (
                request_methods is not None
                and index < len(request_methods)
                and request_methods[index].upper() == "HEAD"
            )
        )

        if no_body:
            body_bytes, end_offset, complete = 0, body_offset, True
        elif chunked:
            body_bytes, end_offset, complete = _measure_chunked(data, body_offset)
        elif declared_length is not None:
            available = max(0, len(data) - body_offset)
            body_bytes = min(declared_length, available)
            end_offset = body_offset + body_bytes
            complete = available >= declared_length
        elif kind == "request":
            body_bytes, end_offset, complete = 0, body_offset, True
        else:
            body_bytes = len(data) - body_offset
            end_offset, complete = len(data), True

        messages.append(
            {
                "start_line": start_line,
                "headers": headers,
                "header_bytes": body_offset - offset,
                "body_offset": body_offset,
                "body_bytes": body_bytes,
                "declared_length": declared_length,
                "chunked": chunked,
                "complete": complete,
                "status_code": status_code,
            }
        )
        index += 1
        if end_offset <= offset:
            break
        offset = end_offset
    return messages


def summarize_multipart(
    body: bytes,
    content_type: bytes,
    watch_fields: list[str],
    max_runs: int = 20,
) -> dict[str, Any] | None:
    """Describe multipart/form-data structure without returning field values.

    Consecutive parts with the same field name are run-length compressed, so a
    body with a thousand numbered parts still produces a short summary.
    """
    match = _BOUNDARY_RE.search(content_type)
    if not match:
        return None
    delimiter = b"--" + match.group(1).strip()
    if len(delimiter) <= 2:
        return None

    part_count = 0
    file_part_count = 0
    largest_part = 0
    runs: list[dict[str, Any]] = []
    first_seen: dict[str, int] = {}
    distinct_names: set[str] = set()
    wanted = set(watch_fields)

    position = body.find(delimiter)
    while position >= 0:
        part_start = position + len(delimiter)
        if body[part_start : part_start + 2] == b"--":
            break
        next_position = body.find(delimiter, part_start)
        part_end = next_position if next_position >= 0 else len(body)
        part = body[part_start:part_end]
        header_end = part.find(b"\r\n\r\n")
        part_headers = part[: header_end if header_end >= 0 else min(len(part), 512)]
        name_match = _NAME_RE.search(part_headers)
        name = _decode(name_match.group(1)) if name_match else "<unnamed>"
        is_file = bool(_FILENAME_RE.search(part_headers))
        part_size = len(part)

        part_count += 1
        file_part_count += int(is_file)
        largest_part = max(largest_part, part_size)
        if name in wanted and name not in first_seen:
            first_seen[name] = position

        key = name + (" [file]" if is_file else "")
        if runs and runs[-1]["field"] == key:
            runs[-1]["count"] += 1
            runs[-1]["bytes"] += part_size
        elif len(runs) < max_runs:
            runs.append({"field": key, "count": 1, "bytes": part_size})
        else:
            if runs[-1]["field"] != "<more>":
                runs.append({"field": "<more>", "count": 0, "bytes": 0})
            runs[-1]["count"] += 1
            runs[-1]["bytes"] += part_size
        distinct_names.add(name)

        if next_position < 0:
            break
        position = next_position

    return {
        "boundary_length": len(delimiter) - 2,
        "part_count": part_count,
        "file_part_count": file_part_count,
        "distinct_field_names": len(distinct_names),
        "largest_part_bytes": largest_part,
        "field_runs": runs,
        "watched_field_offsets": {name: first_seen.get(name) for name in watch_fields},
    }


def set_cookie_anomalies(values: list[bytes]) -> list[dict[str, Any]]:
    """Flag Set-Cookie values that carry binary data or heavy percent-encoding.

    Session identifiers are normally short printable tokens. A cookie whose
    value decodes to non-printable bytes is a strong sign that server memory
    was reflected back to the client.
    """
    findings: list[dict[str, Any]] = []
    for raw in values:
        cookie_pair = raw.split(b";", 1)[0]
        name, _, value = cookie_pair.partition(b"=")
        decoded = unquote_to_bytes(value)
        non_printable = sum(1 for byte in decoded if byte < 0x20 or byte > 0x7E)
        escapes = len(_PERCENT_ESCAPE_RE.findall(value))
        if non_printable or escapes >= 8 or len(decoded) > 256:
            findings.append(
                {
                    "cookie": _truncate(_decode(name.strip()), 64),
                    "decoded_length": len(decoded),
                    "percent_escapes": escapes,
                    "non_printable_bytes": non_printable,
                }
            )
    return findings


def describe_request(
    data: bytes, message: dict[str, Any], watch_fields: list[str], max_runs: int
) -> dict[str, Any]:
    """Build the public description of one HTTP request."""
    method, _, rest = message["start_line"].partition(" ")
    target, _, version = rest.rpartition(" ")
    headers = message["headers"]
    description: dict[str, Any] = {
        "method": method,
        "target": _truncate(target or rest),
        "version": version,
        "headers": _select_headers(headers, REQUEST_HEADERS),
        "declared_content_length": message["declared_length"],
        "body_bytes_captured": message["body_bytes"],
        "chunked": message["chunked"],
        "complete": message["complete"],
    }
    content_type = _header_value(headers, "content-type") or b""
    if b"multipart/form-data" in content_type.lower() and message["body_bytes"]:
        body = data[message["body_offset"] : message["body_offset"] + message["body_bytes"]]
        multipart = summarize_multipart(body, content_type, watch_fields, max_runs)
        if multipart is not None:
            description["multipart"] = multipart
    return description


def describe_response(message: dict[str, Any]) -> dict[str, Any]:
    """Build the public description of one HTTP response."""
    _, _, rest = message["start_line"].partition(" ")
    code_text, _, reason = rest.partition(" ")
    headers = message["headers"]
    cookies = [value for name, value in headers if name == "set-cookie"]
    return {
        "status_code": int(code_text) if code_text.isdigit() else None,
        "reason": _truncate(reason, 64),
        "headers": _select_headers(headers, RESPONSE_HEADERS),
        "declared_content_length": message["declared_length"],
        "body_bytes_captured": message["body_bytes"],
        "complete": message["complete"],
        "set_cookie_anomalies": set_cookie_anomalies(cookies),
    }
