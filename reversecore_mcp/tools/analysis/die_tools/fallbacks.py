"""Zero-dependency pure Python PE and ELF header parsing fallbacks using standard library struct."""

from __future__ import annotations

import struct
from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.tools.analysis.die_tools.anomalies import is_standard_section_name
from reversecore_mcp.tools.analysis.die_tools.entropy import calculate_shannon_entropy

logger = get_logger(__name__)


def _pure_python_pe_fallback(data: bytes) -> dict[str, Any] | None:
    """Parse PE binary headers and sections using standard library `struct`."""
    if len(data) < 64 or data[:2] != b"MZ":
        return None

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return None

        # COFF File Header
        machine, num_sections, _, _, _, opt_hdr_size, characteristics = struct.unpack_from(
            "<HHIIIHH", data, e_lfanew + 4
        )

        is_64 = False
        if machine == 0x8664:  # AMD64
            file_type = "PE32+"
            arch = "x64"
            is_64 = True
        elif machine == 0x14C:  # I386
            file_type = "PE32"
            arch = "x86"
        elif machine == 0xAA64:  # ARM64
            file_type = "PE32+"
            arch = "arm64"
            is_64 = True
        elif machine in (0x1C0, 0x1C4):  # ARM
            file_type = "PE32"
            arch = "arm"
        else:
            file_type = "PE32"
            arch = "unknown"

        entry_point = 0
        size_of_headers = 0
        sec_dir_offset = 0
        sec_dir_size = 0

        opt_offset = e_lfanew + 24
        if opt_hdr_size >= 2:
            magic = struct.unpack_from("<H", data, opt_offset)[0]
            if magic == 0x20B:  # PE32+
                is_64 = True
                file_type = "PE32+"
                if arch == "unknown":
                    arch = "x64"

            if not is_64 and opt_hdr_size >= 96:
                entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
                size_of_headers = struct.unpack_from("<I", data, opt_offset + 60)[0]
                rva_count = struct.unpack_from("<I", data, opt_offset + 92)[0]
                if rva_count >= 5 and (opt_offset + 96 + 4 * 8 + 8) <= len(data):
                    sec_dir_offset, sec_dir_size = struct.unpack_from(
                        "<II", data, opt_offset + 96 + 4 * 8
                    )
            elif is_64 and opt_hdr_size >= 112:
                entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
                size_of_headers = struct.unpack_from("<I", data, opt_offset + 60)[0]
                rva_count = struct.unpack_from("<I", data, opt_offset + 108)[0]
                if rva_count >= 5 and (opt_offset + 112 + 4 * 8 + 8) <= len(data):
                    sec_dir_offset, sec_dir_size = struct.unpack_from(
                        "<II", data, opt_offset + 112 + 4 * 8
                    )

        sec_table_offset = opt_offset + opt_hdr_size
        sections: list[dict[str, Any]] = []
        max_extent = size_of_headers

        for i in range(num_sections):
            sec_offset = sec_table_offset + (i * 40)
            if sec_offset + 40 > len(data):
                break

            name_raw = data[sec_offset : sec_offset + 8]
            name = name_raw.split(b"\x00")[0].decode("ascii", errors="ignore").strip()

            v_size, v_addr, r_size, r_ptr, _, _, _, _, chars = struct.unpack_from(
                "<IIIIIIHHI", data, sec_offset + 8
            )

            is_readable = bool(chars & 0x40000000)
            is_writable = bool(chars & 0x80000000)
            is_executable = bool(chars & 0x20000000)

            # Section raw bytes entropy
            sec_entropy = 0.0
            if r_size > 0 and r_ptr < len(data):
                sec_slice = data[r_ptr : min(r_ptr + r_size, len(data))]
                sec_entropy = calculate_shannon_entropy(sec_slice)
                if (r_ptr + r_size) > max_extent:
                    max_extent = r_ptr + r_size

            sections.append(
                {
                    "name": name,
                    "virtual_address": hex(v_addr),
                    "virtual_size": v_size,
                    "raw_size": r_size,
                    "raw_offset": r_ptr,
                    "size": max(v_size, r_size),
                    "entropy": sec_entropy,
                    "is_readable": is_readable,
                    "is_writable": is_writable,
                    "is_executable": is_executable,
                    "characteristics": chars,
                    "is_standard_name": is_standard_section_name(name, "PE"),
                }
            )

        return {
            "format": file_type,
            "file_type": file_type,
            "arch": arch,
            "entry_point": hex(entry_point) if entry_point else None,
            "sections": sections,
            "security_directory": {
                "offset": sec_dir_offset,
                "size": sec_dir_size,
            },
            "physical_extent": max_extent,
        }
    except Exception as exc:
        logger.debug(f"Pure Python PE fallback error: {exc}")
        return None


def _pure_python_elf_fallback(data: bytes) -> dict[str, Any] | None:
    """Parse ELF binary headers and sections using standard library `struct`."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None

    try:
        ei_class = data[4]  # 1=32-bit, 2=64-bit
        ei_data = data[5]  # 1=LSB, 2=MSB
        endian = "<" if ei_data == 1 else ">"

        is_64 = ei_class == 2
        file_type = "ELF64" if is_64 else "ELF32"

        if is_64:
            if len(data) < 64:
                return None
            (
                e_type,
                e_machine,
                _,
                e_entry,
                e_phoff,
                e_shoff,
                _,
                e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
            ) = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
        else:
            (
                e_type,
                e_machine,
                _,
                e_entry,
                e_phoff,
                e_shoff,
                _,
                e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
            ) = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)

        # Architecture mapping
        if e_machine in (0x3E, 62):  # x86-64
            arch = "x64"
        elif e_machine in (0x03, 3):  # 386
            arch = "x86"
        elif e_machine in (0xB7, 183):  # AArch64
            arch = "arm64"
        elif e_machine in (0x28, 40):  # ARM
            arch = "arm"
        else:
            arch = "unknown"

        # Calculate extent from program headers and section headers
        max_extent = max(
            e_ehsize,
            e_phoff + (e_phentsize * e_phnum) if e_phoff > 0 else 0,
            e_shoff + (e_shentsize * e_shnum) if e_shoff > 0 else 0,
        )

        # Program headers extent
        if e_phoff > 0 and e_phnum > 0 and e_phentsize >= (32 if not is_64 else 56):
            for i in range(e_phnum):
                ph_off = e_phoff + (i * e_phentsize)
                if ph_off + e_phentsize > len(data):
                    break
                if is_64:
                    (
                        p_type,
                        p_flags,
                        p_offset,
                        p_vaddr,
                        p_paddr,
                        p_filesz,
                        p_memsz,
                        p_align,
                    ) = struct.unpack_from(endian + "IIQQQQQQ", data, ph_off)
                else:
                    (
                        p_type,
                        p_offset,
                        p_vaddr,
                        p_paddr,
                        p_filesz,
                        p_memsz,
                        p_flags,
                        p_align,
                    ) = struct.unpack_from(endian + "IIIIIIII", data, ph_off)
                if p_offset + p_filesz > max_extent:
                    max_extent = p_offset + p_filesz

        # Read section string table
        shstrtab_data = b""
        if e_shstrndx < e_shnum and e_shoff > 0 and e_shentsize >= (40 if not is_64 else 64):
            shstr_hdr_off = e_shoff + (e_shstrndx * e_shentsize)
            if shstr_hdr_off + e_shentsize <= len(data):
                if is_64:
                    sh_off = struct.unpack_from(endian + "Q", data, shstr_hdr_off + 24)[0]
                    sh_sz = struct.unpack_from(endian + "Q", data, shstr_hdr_off + 32)[0]
                else:
                    sh_off = struct.unpack_from(endian + "I", data, shstr_hdr_off + 16)[0]
                    sh_sz = struct.unpack_from(endian + "I", data, shstr_hdr_off + 20)[0]
                if sh_off + sh_sz <= len(data):
                    shstrtab_data = data[sh_off : sh_off + sh_sz]

        # Extract sections
        sections: list[dict[str, Any]] = []
        if e_shoff > 0 and e_shnum > 0 and e_shentsize >= (40 if not is_64 else 64):
            for i in range(e_shnum):
                sh_hdr_off = e_shoff + (i * e_shentsize)
                if sh_hdr_off + e_shentsize > len(data):
                    break
                if is_64:
                    sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size = (
                        struct.unpack_from(endian + "IIQQQQ", data, sh_hdr_off)
                    )
                else:
                    sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size = (
                        struct.unpack_from(endian + "IIIIII", data, sh_hdr_off)
                    )

                sec_name = ""
                if shstrtab_data and sh_name_idx < len(shstrtab_data):
                    sec_name = (
                        shstrtab_data[sh_name_idx:]
                        .split(b"\x00")[0]
                        .decode("utf-8", errors="ignore")
                    )

                sec_entropy = 0.0
                if sh_size > 0 and sh_offset < len(data) and sh_type != 8:  # SHT_NOBITS
                    sec_slice = data[sh_offset : min(sh_offset + sh_size, len(data))]
                    sec_entropy = calculate_shannon_entropy(sec_slice)
                    if (sh_offset + sh_size) > max_extent:
                        max_extent = sh_offset + sh_size

                is_writable = bool(sh_flags & 0x1)  # SHF_WRITE
                is_alloc = bool(sh_flags & 0x2)  # SHF_ALLOC
                is_executable = bool(sh_flags & 0x4)  # SHF_EXECINSTR

                sections.append(
                    {
                        "name": sec_name,
                        "virtual_address": hex(sh_addr),
                        "virtual_size": sh_size if is_alloc else 0,
                        "raw_size": sh_size if sh_type != 8 else 0,
                        "raw_offset": sh_offset,
                        "size": sh_size,
                        "entropy": sec_entropy,
                        "is_writable": is_writable,
                        "is_executable": is_executable,
                        "flags": sh_flags,
                        "is_standard_name": is_standard_section_name(sec_name, "ELF"),
                    }
                )

        return {
            "format": file_type,
            "file_type": file_type,
            "arch": arch,
            "entry_point": hex(e_entry) if e_entry else None,
            "sections": sections,
            "security_directory": None,
            "physical_extent": max_extent,
        }
    except Exception as exc:
        logger.debug(f"Pure Python ELF fallback error: {exc}")
        return None


def _pure_python_header_fallback(data: bytes) -> dict[str, Any] | None:
    """Zero-dependency parser fallback for PE and ELF headers using `struct`."""
    if not data:
        return None
    if data.startswith(b"MZ"):
        return _pure_python_pe_fallback(data)
    elif data.startswith(b"\x7fELF"):
        return _pure_python_elf_fallback(data)
    return None


__all__ = [
    "_pure_python_elf_fallback",
    "_pure_python_header_fallback",
    "_pure_python_pe_fallback",
]
