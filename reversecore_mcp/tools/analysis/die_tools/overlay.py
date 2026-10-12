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
        }

    overlay_ratio = round(overlay_size / total_size, 4)
    overlay_entropy = calculate_shannon_entropy(overlay_data)

    payload_type = "Raw_Data"
    description = f"Appended overlay of {overlay_size} bytes ({overlay_ratio * 100:.1f}% of file)"

    # Payload magic classifier
    # 1. Authenticode Certificate Directory
    if (
        sec_dir_offset > 0
        and sec_dir_offset >= extent
        and sec_dir_size > 0
        and (sec_dir_offset + sec_dir_size) <= (total_size + 64)
    ):
        payload_type = "Authenticode_Signature"
        description = (
            f"Valid Authenticode Security Directory (WIN_CERTIFICATE, {sec_dir_size} bytes)"
        )
    elif len(overlay_data) >= 8:
        # Check WIN_CERTIFICATE struct: dwLength (DWORD), wRevision (WORD), wCertificateType (WORD)
        dw_len, w_rev, w_type = struct.unpack_from("<IHH", overlay_data, 0)
        if w_rev in (0x0100, 0x0200) and w_type in (0x0001, 0x0002, 0x0003, 0x0004):
            payload_type = "Authenticode_Signature"
            description = (
                f"Authenticode WIN_CERTIFICATE signature block (type=0x{w_type:04x}, len={dw_len})"
            )

    if payload_type == "Raw_Data":
        # 2. PyInstaller Archive
        if (
            b"MEI\x0c\x0b\x0a\x0b\x0e" in overlay_data
            or b"_MEIPASS" in overlay_data
            or b"pyimod01_os_path" in overlay_data
            or b"base_library.zip" in overlay_data
        ):
            payload_type = "PyInstaller_Archive"
            description = "PyInstaller bundled archive container"
        # 3. ZIP Archive
        elif overlay_data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            payload_type = "ZIP_Archive"
            description = "Appended ZIP archive or package"
        # 4. 7-Zip Archive
        elif overlay_data.startswith(b"7z\xbc\xaf\x27\x1c"):
            payload_type = "7z_Archive"
            description = "Appended 7-Zip compressed payload"
        # 5. RAR Archive
        elif overlay_data.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
            payload_type = "RAR_Archive"
            description = "Appended RAR compressed archive"
        # 6. Microsoft CAB
        elif overlay_data.startswith(b"MSCF"):
            payload_type = "CAB_Archive"
            description = "Appended Microsoft Cabinet archive"
        # 7. NSIS Installer
        elif b"NullsoftInst" in overlay_data or b"\xef\xbe\xad\xdeNullsoftInst" in overlay_data:
            payload_type = "NSIS_Payload"
            description = "Nullsoft Scriptable Install System (NSIS) payload"
        # 8. Inno Setup
        elif (
            b"Inno Setup Setup Data" in overlay_data
            or b"Inno Setup" in overlay_data
            or b"rlebInno" in overlay_data
        ):
            payload_type = "Inno_Setup_Payload"
            description = "Inno Setup installer payload"
        # 9. Tar Archive
        elif len(overlay_data) > 262 and overlay_data[257:262] == b"ustar":
            payload_type = "Tar_Archive"
            description = "Appended POSIX tar archive"
        # 10. Gzip / Bzip2
        elif overlay_data.startswith(b"\x1f\x8b"):
            payload_type = "Gzip_Archive"
            description = "Appended Gzip compressed stream"
        elif overlay_data.startswith(b"BZh"):
            payload_type = "Bzip2_Archive"
            description = "Appended Bzip2 compressed stream"
        # 11. Embedded PE Binary
        elif overlay_data.startswith(b"MZ") and len(overlay_data) >= 64:
            payload_type = "Embedded_PE_Binary"
            description = "Embedded Executable (PE) binary in overlay"
        # 12. High-Entropy Encrypted / Compressed Blob
        elif overlay_entropy >= 7.2:
            payload_type = "Encrypted_or_Compressed_Blob"
            description = f"High-entropy opaque payload (entropy={overlay_entropy:.2f})"

    return {
        "has_overlay": True,
        "offset": extent,
        "size": overlay_size,
        "ratio": overlay_ratio,
        "entropy": overlay_entropy,
        "payload_type": payload_type,
        "description": description,
    }


__all__ = [
    "inspect_binary_overlay",
]
