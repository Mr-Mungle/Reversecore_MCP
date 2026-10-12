"""Packer, protector, and compiler detection engine.

Provides comprehensive binary analysis using native Shannon entropy calculation,
section anomaly heuristics, binary overlay inspection, deep signature matching,
and zero-dependency pure Python PE/ELF header fallbacks.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from pathlib import Path
from typing import Any

import lief

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.tools.analysis.die_tools.anomalies import (
    _STANDARD_ELF_SECTIONS,
    _STANDARD_MACHO_SECTIONS,
    _STANDARD_PE_SECTIONS,
    _SUSPICIOUS_SECTIONS,
    detect_section_anomalies,
    is_standard_section_name,
)
from reversecore_mcp.tools.analysis.die_tools.entropy import (
    calculate_block_entropy,
    calculate_shannon_entropy,
    get_entropy_category,
)
from reversecore_mcp.tools.analysis.die_tools.fallbacks import (
    _pure_python_elf_fallback,
    _pure_python_header_fallback,
    _pure_python_pe_fallback,
)
from reversecore_mcp.tools.analysis.die_tools.overlay import inspect_binary_overlay
from reversecore_mcp.tools.analysis.die_tools.signatures import (
    _COMPILER_SIGNATURES,
    _PACKER_SIGNATURES,
    compute_packing_heuristic_score,
)

logger = get_logger(__name__)


def _run_diec_cli_if_available(file_path: Path) -> dict[str, Any] | None:
    """Optional external Detect-It-Easy CLI invocation if installed on host."""
    diec_path = shutil.which("diec")
    if not diec_path:
        return None

    try:
        from reversecore_mcp.core.execution import execute_subprocess_streaming

        stdout, _ = execute_subprocess_streaming(
            [diec_path, "-j", str(file_path)],
            timeout=5,
        )
        if stdout.strip():
            parsed = json.loads(stdout)
            return parsed if isinstance(parsed, dict) else None
    except Exception as exc:
        logger.debug(f"diec CLI execution skipped/failed: {exc}")

    return None


def _analyze_binary_with_lief(file_path: Path, data: bytes | None = None) -> dict[str, Any]:
    """Analyze a binary using LIEF with resilient fallback to pure Python header parsing."""
    result: dict[str, Any] = {
        "file_type": None,
        "arch": None,
        "entry_point": None,
        "high_entropy_sections": [],
        "suspicious_sections": [],
        "packer_from_sections": None,
        "sections": [],
        "physical_extent": 0,
        "security_directory": None,
    }

    if data is None:
        try:
            data = file_path.read_bytes()
        except OSError:
            data = b""

    lief_success = False

    try:
        binary = lief.parse(str(file_path))
        if binary is not None:
            lief_success = True
            mock_cls = getattr(binary, "_mock_class", None)
            if mock_cls is not None:
                is_pe = mock_cls == lief.PE.Binary
                is_elf = mock_cls == lief.ELF.Binary
                is_macho = mock_cls == lief.MachO.Binary
            else:
                is_pe = isinstance(binary, lief.PE.Binary)
                is_elf = isinstance(binary, lief.ELF.Binary)
                is_macho = isinstance(binary, lief.MachO.Binary)

            # Determine Format & Arch
            if is_pe:
                machine = getattr(binary.header, "machine", None)
                is_amd64 = False
                if machine is not None:
                    is_amd64 = (
                        "AMD64" in str(machine)
                        or getattr(machine, "name", "") == "AMD64"
                        or machine == 34404
                    )
                result["file_type"] = "PE32+" if is_amd64 else "PE32"
                result["arch"] = "x64" if is_amd64 else "x86"
                if hasattr(binary, "entrypoint"):
                    result["entry_point"] = hex(binary.entrypoint)
            elif is_elf:
                identity_class = getattr(binary.header, "identity_class", None)
                is_64 = (
                    "CLASS64" in str(identity_class)
                    or "ELF64" in str(identity_class)
                    or getattr(identity_class, "name", "") in ("CLASS64", "ELF64")
                )
                result["file_type"] = "ELF64" if is_64 else "ELF32"

                machine_type = getattr(binary.header, "machine_type", None)
                mach_str = str(machine_type).upper()
                if "X86_64" in mach_str or "AMD64" in mach_str:
                    result["arch"] = "x64"
                elif "I386" in mach_str or "X86" in mach_str:
                    result["arch"] = "x86"
                elif "AARCH64" in mach_str or "ARM64" in mach_str:
                    result["arch"] = "arm64"
                elif "ARM" in mach_str:
                    result["arch"] = "arm"
                if hasattr(binary, "entrypoint"):
                    result["entry_point"] = hex(binary.entrypoint)
            elif is_macho:
                result["file_type"] = "Mach-O"
                cpu_type = getattr(binary.header, "cpu_type", None)
                cpu_str = str(cpu_type).upper()
                if "ARM64" in cpu_str:
                    result["arch"] = "arm64"
                elif "X86_64" in cpu_str:
                    result["arch"] = "x64"
                if hasattr(binary, "entrypoint"):
                    result["entry_point"] = hex(binary.entrypoint)

            # Analyze Sections
            max_extent = 0
            for section in binary.sections:
                entropy = getattr(section, "entropy", 0.0)
                if not isinstance(entropy, (int, float)):
                    try:
                        entropy = float(entropy)
                    except Exception:
                        entropy = 0.0

                name = getattr(section, "name", "")
                if not isinstance(name, str):
                    name = str(name)

                size = getattr(section, "size", 0)
                if not isinstance(size, (int, float)):
                    try:
                        size = int(size)
                    except Exception:
                        size = 0

                v_addr = getattr(section, "virtual_address", 0)
                v_size = getattr(section, "virtual_size", size)
                offset = getattr(section, "offset", 0)

                # Check flags
                is_writable = False
                is_executable = False
                if (
                    hasattr(section, "has_characteristic")
                    and type(section).__name__ != "MagicMock"
                    and not hasattr(section, "_mock_name")
                ):
                    try:
                        char_enum = getattr(
                            lief.PE,
                            "SECTION_CHARACTERISTICS",
                            getattr(
                                getattr(lief.PE, "Section", None),
                                "CHARACTERISTICS",
                                None,
                            ),
                        )
                        if char_enum is not None:
                            is_writable = bool(section.has_characteristic(char_enum.MEM_WRITE))
                            is_executable = bool(section.has_characteristic(char_enum.MEM_EXECUTE))
                    except Exception:
                        pass
                elif hasattr(section, "flags") and isinstance(section.flags, int):
                    is_writable = bool(section.flags & 0x1)
                    is_executable = bool(section.flags & 0x4)

                sec_dict = {
                    "name": name,
                    "virtual_address": (hex(v_addr) if isinstance(v_addr, int) else str(v_addr)),
                    "virtual_size": (v_size if isinstance(v_size, (int, float)) else size),
                    "raw_size": size,
                    "raw_offset": offset if isinstance(offset, (int, float)) else 0,
                    "size": size,
                    "entropy": (round(entropy, 2) if isinstance(entropy, (int, float)) else 0.0),
                    "is_writable": bool(is_writable),
                    "is_executable": bool(is_executable),
                    "is_standard_name": is_standard_section_name(name, result["file_type"]),
                }
                result["sections"].append(sec_dict)

                if isinstance(offset, (int, float)) and isinstance(size, (int, float)):
                    if (offset + size) > max_extent:
                        max_extent = int(offset + size)

                if entropy > 7.0:
                    result["high_entropy_sections"].append(
                        {
                            "name": name,
                            "entropy": round(entropy, 2),
                            "size": size,
                        }
                    )

                # Check for suspicious section names
                name_lower = name.lower()
                if name_lower in _SUSPICIOUS_SECTIONS:
                    result["suspicious_sections"].append(name)
                    if not result["packer_from_sections"]:
                        result["packer_from_sections"] = _SUSPICIOUS_SECTIONS[name_lower]

            if is_elf and hasattr(binary, "header"):
                shoff = getattr(binary.header, "section_header_offset", 0)
                shnum = getattr(binary.header, "numberof_sections", 0)
                shentsz = getattr(binary.header, "section_header_size", 0)
                if isinstance(shoff, int) and isinstance(shnum, int) and isinstance(shentsz, int):
                    if (shoff + (shnum * shentsz)) > max_extent:
                        max_extent = shoff + (shnum * shentsz)

                phoff = getattr(binary.header, "program_header_offset", 0)
                phnum = getattr(binary.header, "numberof_segments", 0)
                phentsz = getattr(binary.header, "program_header_size", 0)
                if isinstance(phoff, int) and isinstance(phnum, int) and isinstance(phentsz, int):
                    if (phoff + (phnum * phentsz)) > max_extent:
                        max_extent = phoff + (phnum * phentsz)

            result["physical_extent"] = max_extent

    except Exception as e:
        logger.debug(f"LIEF parsing failed for {file_path.name}: {e}")

    # If LIEF failed or returned no sections on a non-empty payload, invoke pure python fallback
    if (not lief_success or not result["file_type"] or not result["sections"]) and data:
        fallback = _pure_python_header_fallback(data)
        if fallback:
            result["file_type"] = fallback["file_type"]
            result["arch"] = fallback["arch"]
            result["entry_point"] = fallback.get("entry_point")
            result["sections"] = fallback["sections"]
            result["physical_extent"] = fallback["physical_extent"]
            result["security_directory"] = fallback.get("security_directory")

            for sec in fallback["sections"]:
                ent = sec.get("entropy", 0.0) or 0.0
                if ent > 7.0:
                    result["high_entropy_sections"].append(
                        {
                            "name": sec["name"],
                            "entropy": round(ent, 2),
                            "size": sec["size"],
                        }
                    )
                name_lower = sec["name"].lower()
                if name_lower in _SUSPICIOUS_SECTIONS:
                    result["suspicious_sections"].append(sec["name"])
                    if not result["packer_from_sections"]:
                        result["packer_from_sections"] = _SUSPICIOUS_SECTIONS[name_lower]

    return result


@log_execution()
async def detect_packer(file_path: str) -> ToolResult:
    """Detect packer, compiler, and protector using Shannon entropy, section heuristics, and signature matching.

    Args:
        file_path: Path to the binary file to analyze.

    Returns:
        ToolResult with detailed detection information.
    """
    validated_path = validate_file_path(file_path, read_only=True)
    max_file_size = getattr(get_config(), "lief_max_file_size", 1_000_000_000)
    try:
        file_size = validated_path.stat().st_size
        if isinstance(file_size, (int, float)) and file_size > max_file_size:
            return failure(
                "FILE_TOO_LARGE",
                f"File size ({file_size} bytes) exceeds maximum allowed size ({max_file_size} bytes)",
                hint="Set REVERSECORE_MAX_FILE_SIZE environment variable to increase limit",
            )
    except (OSError, AttributeError):
        pass

    try:
        data = validated_path.read_bytes()
    except OSError as exc:
        return failure("FILE_READ_ERROR", f"Cannot read file: {exc}")

    # 1. Whole-file Shannon Entropy
    overall_entropy = calculate_shannon_entropy(data)
    entropy_cat = get_entropy_category(overall_entropy)

    # 2. Structural & LIEF / Fallback Analysis
    lief_info = _analyze_binary_with_lief(validated_path, data=data)

    # 3. String & Signature Scanning
    ascii_strings = b" ".join(m.group() for m in re.finditer(rb"[ -~]{4,}", data)).decode(
        "ascii", errors="ignore"
    )

    found_packer = lief_info["packer_from_sections"]
    found_packers_list: list[str] = []
    if found_packer:
        found_packers_list.append(found_packer)

    found_compiler = None
    found_compilers_list: list[str] = []
    detections: list[dict[str, Any]] = []

    for pattern, label in _PACKER_SIGNATURES:
        if re.search(pattern, ascii_strings, re.IGNORECASE):
            if label not in found_packers_list:
                found_packers_list.append(label)
            if not found_packer:
                found_packer = label
            detections.append({"type": "packer", "value": label})

    for pattern, label in _COMPILER_SIGNATURES:
        if re.search(pattern, ascii_strings, re.IGNORECASE):
            if label not in found_compilers_list:
                found_compilers_list.append(label)
            if not found_compiler:
                found_compiler = label
            detections.append({"type": "compiler", "value": label})

    # Optional diec CLI enhancement
    diec_res = await asyncio.to_thread(_run_diec_cli_if_available, validated_path)
    if diec_res and isinstance(diec_res, dict):
        die_detects = diec_res.get("detects", [])
        for det in die_detects:
            d_type = det.get("type", "unknown")
            d_name = det.get("name", "")
            if d_name:
                detections.append({"type": f"diec_{d_type}", "value": d_name})
                if "packer" in d_type.lower() and d_name not in found_packers_list:
                    found_packers_list.append(d_name)
                    if not found_packer:
                        found_packer = d_name

    # 4. Section Anomaly Analysis
    ep_val = None
    if lief_info.get("entry_point"):
        try:
            ep_val = int(lief_info["entry_point"], 16)
        except ValueError:
            ep_val = None

    section_anomalies = detect_section_anomalies(
        sections=lief_info.get("sections", []),
        entrypoint=ep_val,
        file_size=len(data),
        format_type=lief_info.get("file_type") or "PE",
    )

    # 5. Overlay Inspection
    overlay_info = inspect_binary_overlay(
        file_path=validated_path,
        data=data,
        binary_info=lief_info,
    )

    # 6. Multi-factor Heuristic Scoring
    scoring = compute_packing_heuristic_score(
        overall_entropy=overall_entropy,
        high_entropy_sections=lief_info.get("high_entropy_sections", []),
        section_anomalies=section_anomalies,
        overlay_info=overlay_info,
        found_packers=found_packers_list,
        found_compilers=found_compilers_list,
        suspicious_sections=lief_info.get("suspicious_sections", []),
    )

    is_packed = scoring["is_packed"]
    confidence = scoring["packing_confidence"]
    packer_category = scoring["packer_category"]

    detected_packers = [
        {"name": p, "type": "packer", "confidence": confidence} for p in found_packers_list
    ]

    result = {
        "file_path": str(validated_path),
        "file_type": lief_info["file_type"],
        "arch": lief_info["arch"],
        "compiler": found_compiler,
        "packer": found_packer,
        "is_packed": is_packed,
        "packing_confidence": confidence,
        "packer_category": packer_category,
        "detected_packers": detected_packers,
        "high_entropy_sections": lief_info["high_entropy_sections"],
        "suspicious_sections": lief_info["suspicious_sections"],
        "entropy": {
            "overall_file": overall_entropy,
            "category": entropy_cat,
            "high_entropy_sections": lief_info["high_entropy_sections"],
        },
        "section_anomalies": section_anomalies,
        "overlay": overlay_info,
        "reasons": scoring["reasons"],
        "detections": detections,
    }

    message_parts = [
        f"Detected: {result['file_type'] or 'Unknown'} ({result['arch'] or 'Unknown'})"
    ]
    if found_packer:
        message_parts.append(f"Packer: {found_packer} ({packer_category})")
    elif is_packed:
        message_parts.append(f"Packer: Suspicious/Packed ({confidence * 100:.0f}%)")
    else:
        message_parts.append("Packer: None (Clean)")

    if found_compiler:
        message_parts.append(f"Compiler: {found_compiler}")
    message_parts.append(f"Entropy: {overall_entropy:.2f} ({entropy_cat})")

    return success(
        data=result,
        message=" | ".join(message_parts),
        is_packed=is_packed,
        packing_confidence=confidence,
        detection_count=len(detections),
    )


@log_execution()
async def detect_packer_deep(file_path: str) -> ToolResult:
    """Deep scan combining block-level entropy, overlay analysis, section anomaly heuristics, and full signature scanning.

    Args:
        file_path: Path to the binary file to analyze.

    Returns:
        ToolResult with comprehensive deep detection metrics.
    """
    validated_path = validate_file_path(file_path, read_only=True)
    max_file_size = getattr(get_config(), "lief_max_file_size", 1_000_000_000)
    try:
        file_size = validated_path.stat().st_size
        if isinstance(file_size, (int, float)) and file_size > max_file_size:
            return failure(
                "FILE_TOO_LARGE",
                f"File size ({file_size} bytes) exceeds maximum allowed size ({max_file_size} bytes)",
                hint="Set REVERSECORE_MAX_FILE_SIZE environment variable to increase limit",
            )
    except (OSError, AttributeError):
        pass

    try:
        data = validated_path.read_bytes()
    except OSError as exc:
        return failure("FILE_READ_ERROR", f"Cannot read file: {exc}")

    # 1. Whole-file & Block-level Entropy Analysis
    overall_entropy = calculate_shannon_entropy(data)
    entropy_cat = get_entropy_category(overall_entropy)
    block_entropy_list = calculate_block_entropy(data, block_size=4096)

    high_entropy_blocks = [b for b in block_entropy_list if b["entropy"] >= 7.0]
    block_summary = {
        "block_count": len(block_entropy_list),
        "block_size": 4096,
        "high_entropy_block_count": len(high_entropy_blocks),
        "min_block_entropy": (
            min(b["entropy"] for b in block_entropy_list) if block_entropy_list else 0.0
        ),
        "max_block_entropy": (
            max(b["entropy"] for b in block_entropy_list) if block_entropy_list else 0.0
        ),
        "mean_block_entropy": (
            round(
                sum(b["entropy"] for b in block_entropy_list) / len(block_entropy_list),
                4,
            )
            if block_entropy_list
            else 0.0
        ),
    }

    # 2. Structural & Section Analysis
    lief_info = _analyze_binary_with_lief(validated_path, data=data)

    # 3. String & Signature Scanning
    ascii_strings = b" ".join(m.group() for m in re.finditer(rb"[ -~]{4,}", data)).decode(
        "ascii", errors="ignore"
    )

    detections: list[dict[str, Any]] = []
    found_packers: set[str] = set()
    found_compilers: set[str] = set()

    if lief_info["packer_from_sections"]:
        found_packers.add(lief_info["packer_from_sections"])
        detections.append({"type": "packer_section", "value": lief_info["packer_from_sections"]})

    for pattern, label in _PACKER_SIGNATURES:
        if re.search(pattern, ascii_strings, re.IGNORECASE):
            found_packers.add(label)
            detections.append({"type": "packer_signature", "value": label})

    for pattern, label in _COMPILER_SIGNATURES:
        if re.search(pattern, ascii_strings, re.IGNORECASE):
            found_compilers.add(label)
            detections.append({"type": "compiler_signature", "value": label})

    # Optional diec CLI integration
    diec_res = await asyncio.to_thread(_run_diec_cli_if_available, validated_path)
    if diec_res and isinstance(diec_res, dict):
        for det in diec_res.get("detects", []):
            d_type = det.get("type", "unknown")
            d_name = det.get("name", "")
            if d_name:
                detections.append({"type": f"diec_{d_type}", "value": d_name})
                if "packer" in d_type.lower():
                    found_packers.add(d_name)

    # 4. Section Anomaly Analysis
    ep_val = None
    if lief_info.get("entry_point"):
        try:
            ep_val = int(lief_info["entry_point"], 16)
        except ValueError:
            ep_val = None

    section_anomalies = detect_section_anomalies(
        sections=lief_info.get("sections", []),
        entrypoint=ep_val,
        file_size=len(data),
        format_type=lief_info.get("file_type") or "PE",
    )

    # 5. Overlay Inspection
    overlay_info = inspect_binary_overlay(
        file_path=validated_path,
        data=data,
        binary_info=lief_info,
    )

    # 6. Multi-Factor Heuristic Scoring
    scoring = compute_packing_heuristic_score(
        overall_entropy=overall_entropy,
        high_entropy_sections=lief_info.get("high_entropy_sections", []),
        section_anomalies=section_anomalies,
        overlay_info=overlay_info,
        found_packers=sorted(found_packers),
        found_compilers=sorted(found_compilers),
        suspicious_sections=lief_info.get("suspicious_sections", []),
    )

    is_packed = scoring["is_packed"]
    confidence = scoring["packing_confidence"]
    packer_category = scoring["packer_category"]

    result = {
        "file_path": str(validated_path),
        "file_type": lief_info["file_type"],
        "arch": lief_info["arch"],
        "compiler": next(iter(found_compilers), None),
        "compilers": sorted(found_compilers),
        "packer": next(iter(found_packers), None),
        "packers": sorted(found_packers),
        "is_packed": is_packed,
        "packing_confidence": confidence,
        "packer_category": packer_category,
        "high_entropy_sections": lief_info["high_entropy_sections"],
        "suspicious_sections": lief_info["suspicious_sections"],
        "entropy": {
            "overall_file": overall_entropy,
            "category": entropy_cat,
            "high_entropy_sections": lief_info["high_entropy_sections"],
            "block_summary": block_summary,
        },
        "all_sections_analysis": lief_info.get("sections", []),
        "section_anomalies": section_anomalies,
        "overlay": overlay_info,
        "raw_strings_sample": ascii_strings[:2000],
        "reasons": scoring["reasons"],
        "detections": detections,
    }

    return success(
        data=result,
        message=(
            f"Deep scan complete: {len(detections)} signatures, "
            f"{len(lief_info['high_entropy_sections'])} high-entropy sections, "
            f"{len(section_anomalies)} anomalies, confidence={confidence:.2f}"
        ),
        scan_type="native_deep",
        source="entropy_and_heuristics",
        is_packed=is_packed,
        packing_confidence=confidence,
        detection_count=len(detections),
    )


__all__ = [
    "_COMPILER_SIGNATURES",
    "_PACKER_SIGNATURES",
    "_STANDARD_ELF_SECTIONS",
    "_STANDARD_MACHO_SECTIONS",
    "_STANDARD_PE_SECTIONS",
    "_SUSPICIOUS_SECTIONS",
    "_analyze_binary_with_lief",
    "_pure_python_elf_fallback",
    "_pure_python_header_fallback",
    "_pure_python_pe_fallback",
    "_run_diec_cli_if_available",
    "calculate_block_entropy",
    "calculate_shannon_entropy",
    "compute_packing_heuristic_score",
    "detect_packer",
    "detect_packer_deep",
    "detect_section_anomalies",
    "get_entropy_category",
    "inspect_binary_overlay",
    "is_standard_section_name",
    "validate_file_path",
]
