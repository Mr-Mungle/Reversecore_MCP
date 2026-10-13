"""Binary overlay inspection and trailing payload classifier engine."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from reversecore_mcp.tools.analysis.die_tools.entropy import calculate_shannon_entropy
from reversecore_mcp.tools.analysis.die_tools.fallbacks import (
    _pure_python_header_fallback,
)


def inspect_binary_overlay(
    file_path: Path | None,
    data: bytes,
    binary_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Inspect and classify trailing overlay data appended beyond valid binary headers and sections.

    Args:
        file_path: Optional path to binary file.
        data: Raw binary byte sequence.
        binary_info: Extracted binary metadata containing physical extent, security directory, etc.

    Returns:
        Dictionary containing overlay metrics and payload classification.
    """
    total_size = len(data)
    if total_size == 0:
        return {
            "has_overlay": False,
            "offset": 0,
            "size": 0,
            "ratio": 0.0,
            "entropy": 0.0,
            "payload_type": "None",
            "description": "Empty file",
            "certificate": None,
            "trailing_payload": None,
        }

    extent = 0
    sec_dir_offset = 0
    sec_dir_size = 0

    if binary_info:
        extent = binary_info.get("physical_extent", 0)
        sec_dir = binary_info.get("security_directory") or {}
        if isinstance(sec_dir, dict):
            sec_dir_offset = sec_dir.get("offset", 0)
            sec_dir_size = sec_dir.get("size", 0)

    # If extent was not provided, attempt pure python fallback to calculate physical extent
    if extent <= 0:
        fb = _pure_python_header_fallback(data)
        if fb:
            extent = fb.get("physical_extent", 0)
            sec_dir = fb.get("security_directory") or {}
            sec_dir_offset = sec_dir.get("offset", 0)
            sec_dir_size = sec_dir.get("size", 0)

    # Clamp extent to valid range
    if extent <= 0 or extent >= total_size:
        return {
            "has_overlay": False,
            "offset": total_size,
            "size": 0,
            "ratio": 0.0,
            "entropy": 0.0,
            "payload_type": "None",
            "description": "No overlay detected; file ends at valid section table boundaries",
            "certificate": None,
            "trailing_payload": None,
        }

    overlay_size = total_size - extent
    overlay_data = data[extent:]

    # Ignore negligible alignment padding (e.g. <= 64 bytes of pure nulls)
    if overlay_size <= 64 and overlay_data.strip(b"\x00") == b"":
        return {
            "has_overlay": False,
            "offset": total_size,
            "size": 0,
            "ratio": 0.0,
            "entropy": 0.0,
            "payload_type": "None",
            "description": "File ends with standard section alignment padding",
            "certificate": None,
            "trailing_payload": None,
        }

    overlay_ratio = round(overlay_size / total_size, 4)
    overlay_entropy = calculate_shannon_entropy(overlay_data)

    certificate_info: dict[str, Any] | None = None
    trailing_payload_info: dict[str, Any] | None = None

    # Authenticode certificate detection:
    # 1. Valid security directory from PE headers
    has_sec_dir = (
        sec_dir_offset > 0
        and sec_dir_offset >= extent
        and sec_dir_size >= 8
        and (sec_dir_offset + sec_dir_size) <= (total_size + 64)
    )

    cert_offset = 0
    cert_size = 0

    if has_sec_dir:
        cert_offset = sec_dir_offset
        cert_size = sec_dir_size
        certificate_info = {
            "offset": cert_offset,
            "size": cert_size,
        }
        if cert_offset + 8 <= total_size:
            dw_len, w_rev, w_type = struct.unpack_from("<IHH", data, cert_offset)
            certificate_info["revision"] = w_rev
            certificate_info["certificate_type"] = w_type
    elif len(overlay_data) >= 8:
        # 2. Heuristic WIN_CERTIFICATE struct: dwLength (DWORD), wRevision (WORD), wCertificateType (WORD)
        dw_len, w_rev, w_type = struct.unpack_from("<IHH", overlay_data, 0)
        # Bounds check dw_len: must be at least 8 bytes and not exceed available overlay data
        if (
            8 <= dw_len <= len(overlay_data)
            and w_rev in (0x0100, 0x0200)
            and w_type in (0x0001, 0x0002, 0x0003, 0x0004)
        ):
            cert_offset = extent
            cert_size = dw_len
            certificate_info = {
                "offset": cert_offset,
                "size": cert_size,
                "revision": w_rev,
                "certificate_type": w_type,
            }

    if certificate_info is not None:
        raw_cert_end = cert_offset + cert_size
        aligned_cert_end = min((raw_cert_end + 7) & ~7, total_size)
        trailing_data = data[aligned_cert_end:]
        trailing_size = len(trailing_data)

        # Check if trailing data is a meaningful payload (not just alignment slack/padding)
        is_meaningful_payload = False
        trailing_type = "None"
        trailing_desc = ""
        trailing_entropy = 0.0

        if trailing_size > 8:
            trailing_type, trailing_desc, trailing_entropy = _classify_payload_magic(trailing_data)
            if trailing_type != "Raw_Data":
                is_meaningful_payload = True
            elif trailing_size > 64 and trailing_data.strip(b"\x00") != b"":
                is_meaningful_payload = True

        if not is_meaningful_payload:
            payload_type = "Authenticode_Signature"
            description = (
                f"Valid Authenticode Security Directory (WIN_CERTIFICATE, {cert_size} bytes)"
            )
            trailing_payload_info = None
        else:
            trailing_payload_info = {
                "offset": aligned_cert_end,
                "size": trailing_size,
                "entropy": round(trailing_entropy, 4),
                "payload_type": trailing_type,
                "description": trailing_desc,
            }
            payload_type = trailing_type
            description = (
                f"Authenticode signature ({cert_size} bytes) with appended {trailing_type} payload "
                f"({trailing_size} bytes)"
            )
    else:
        payload_type, description, _ = _classify_payload_magic(overlay_data)

    return {
        "has_overlay": True,
        "offset": extent,
        "size": overlay_size,
        "ratio": overlay_ratio,
        "entropy": overlay_entropy,
        "payload_type": payload_type,
        "description": description,
        "certificate": certificate_info,
        "trailing_payload": trailing_payload_info,
    }


def _classify_payload_magic(payload_data: bytes) -> tuple[str, str, float]:
    """Classify payload bytes by known container/archive magics or entropy.

    Returns:
        (payload_type, description, entropy)
    """
    entropy = calculate_shannon_entropy(payload_data)
    payload_type = "Raw_Data"
    description = f"Appended overlay payload ({len(payload_data)} bytes)"

    # 1. PyInstaller Archive
    if (
        b"MEI\x0c\x0b\x0a\x0b\x0e" in payload_data
        or b"_MEIPASS" in payload_data
        or b"pyimod01_os_path" in payload_data
        or b"base_library.zip" in payload_data
    ):
        payload_type = "PyInstaller_Archive"
        description = "PyInstaller bundled archive container"
    # 2. ZIP Archive
    elif payload_data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        payload_type = "ZIP_Archive"
        description = "Appended ZIP archive or package"
    # 3. 7-Zip Archive
    elif payload_data.startswith(b"7z\xbc\xaf\x27\x1c"):
        payload_type = "7z_Archive"
        description = "Appended 7-Zip compressed payload"
    # 4. RAR Archive
    elif payload_data.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        payload_type = "RAR_Archive"
        description = "Appended RAR compressed archive"
    # 5. Microsoft CAB
    elif payload_data.startswith(b"MSCF"):
        payload_type = "CAB_Archive"
        description = "Appended Microsoft Cabinet archive"
    # 6. NSIS Installer
    elif b"NullsoftInst" in payload_data or b"\xef\xbe\xad\xdeNullsoftInst" in payload_data:
        payload_type = "NSIS_Payload"
        description = "Nullsoft Scriptable Install System (NSIS) payload"
    # 7. Inno Setup
    elif (
        b"Inno Setup Setup Data" in payload_data
        or b"Inno Setup" in payload_data
        or b"rlebInno" in payload_data
    ):
        payload_type = "Inno_Setup_Payload"
        description = "Inno Setup installer payload"
    # 8. Tar Archive
    elif len(payload_data) > 262 and payload_data[257:262] == b"ustar":
        payload_type = "Tar_Archive"
        description = "Appended POSIX tar archive"
    # 9. Gzip / Bzip2
    elif payload_data.startswith(b"\x1f\x8b"):
        payload_type = "Gzip_Archive"
        description = "Appended Gzip compressed stream"
    elif payload_data.startswith(b"BZh"):
        payload_type = "Bzip2_Archive"
        description = "Appended Bzip2 compressed stream"
    # 10. Embedded PE Binary
    elif payload_data.startswith(b"MZ") and len(payload_data) >= 64:
        payload_type = "Embedded_PE_Binary"
        description = "Embedded Executable (PE) binary in overlay"
    # 11. High-Entropy Encrypted / Compressed Blob
    elif entropy >= 7.2:
        payload_type = "Encrypted_or_Compressed_Blob"
        description = f"High-entropy opaque payload (entropy={entropy:.2f})"

    return payload_type, description, entropy


__all__ = [
    "inspect_binary_overlay",
]
