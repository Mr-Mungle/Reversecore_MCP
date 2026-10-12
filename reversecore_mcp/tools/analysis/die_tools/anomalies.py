"""Section anomaly heuristics, W+X protection checks, and section catalogs."""

from __future__ import annotations

from typing import Any

# Section names known to belong to specific packers / protectors
_SUSPICIOUS_SECTIONS: dict[str, str] = {
    ".upx0": "UPX",
    ".upx1": "UPX",
    ".upx2": "UPX",
    ".upx3": "UPX",
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".vmp2": "VMProtect",
    "vmp0": "VMProtect",
    "vmp1": "VMProtect",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    "aspack": "ASPack",
    "adata": "ASPack",
    "pecompact2": "PECompact",
    "pec2": "PECompact",
    ".pec": "PECompact",
    ".enigma1": "Enigma Protector",
    ".enigma2": "Enigma Protector",
    ".themida": "Themida",
    ".oreans": "Themida",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
    ".nsp0": "NsPack",
    ".nsp1": "NsPack",
    ".nsp2": "NsPack",
    ".petite": "Petite",
    ".fsg": "FSG",
    ".packed": "Unknown Packer",
    ".cpack": "CPack",
    ".ccg": "CCG",
    ".maskpe": "MaskPE",
    ".perplex": "Perplex PE-Protector",
    ".snk": "SUE Packer",
    ".spack": "Simple Pack",
    ".boom": "Boomerang",
    ".svkp": "SVKP",
    ".yoda": "Yoda Protector",
    ".neolite": "NeoLite",
    ".pack": "Generic Packer",
}

# Standard section catalogs across binary formats
_STANDARD_PE_SECTIONS = {
    ".text",
    ".data",
    ".rdata",
    ".bss",
    ".idata",
    ".edata",
    ".rsrc",
    ".reloc",
    ".tls",
    ".pdata",
    ".gfids",
    ".00cfg",
    ".xdata",
    ".cormeta",
    "code",
    "data",
    "text",
    "bss",
    ".didat",
    ".crtdlg",
    ".arch",
    ".sxdata",
    ".wixburn",
    ".debug",
    ".drectve",
    ".corid",
}

_STANDARD_ELF_SECTIONS = {
    ".text",
    ".data",
    ".rodata",
    ".bss",
    ".init",
    ".fini",
    ".ctors",
    ".dtors",
    ".got",
    ".plt",
    ".got.plt",
    ".dynamic",
    ".dynsym",
    ".dynstr",
    ".symtab",
    ".strtab",
    ".rel.text",
    ".rela.text",
    ".rel.data",
    ".rela.data",
    ".rel.dyn",
    ".rela.dyn",
    ".rel.plt",
    ".rela.plt",
    ".comment",
    ".note",
    ".note.gnu.build-id",
    ".note.abi-tag",
    ".note.gnu.property",
    ".interp",
    ".gnu.hash",
    ".hash",
    ".eh_frame",
    ".eh_frame_hdr",
    ".init_array",
    ".fini_array",
    ".tdata",
    ".tbss",
    ".gnu.version",
    ".gnu.version_r",
    ".gnu.version_d",
    ".shstrtab",
}

_STANDARD_MACHO_SECTIONS = {
    "__text",
    "__data",
    "__rodata",
    "__bss",
    "__const",
    "__cstring",
    "__literal4",
    "__literal8",
    "__literal16",
    "__common",
    "__nl_symbol_ptr",
    "__la_symbol_ptr",
    "__mod_init_func",
    "__mod_term_func",
    "__got",
    "__unwind_info",
    "__eh_frame",
    "__textcoal_nt",
    "__picsymbolstub4",
    "__stubs",
    "__stub_helper",
}


def is_standard_section_name(name: str, format_type: str | None = None) -> bool:
    """Check if a section name is standard for PE, ELF, or Mach-O."""
    if not name:
        return False
    clean = name.strip().lower()
    if format_type:
        fmt = format_type.upper()
        if "PE" in fmt:
            return clean in _STANDARD_PE_SECTIONS
        elif "ELF" in fmt:
            return clean in _STANDARD_ELF_SECTIONS
        elif "MACH" in fmt:
            return clean in _STANDARD_MACHO_SECTIONS
    return (
        clean in _STANDARD_PE_SECTIONS
        or clean in _STANDARD_ELF_SECTIONS
        or clean in _STANDARD_MACHO_SECTIONS
    )


def detect_section_anomalies(
    sections: list[dict[str, Any]],
    entrypoint: int | None = None,
    file_size: int = 0,
    format_type: str = "PE",
) -> list[dict[str, Any]]:
    """Detect structural anomalies, W+X violations, and size disparities in binary sections.

    Args:
        sections: List of section dicts (name, virtual_address, virtual_size, raw_size, entropy, etc.).
        entrypoint: Optional entrypoint address (VA or RVA).
        file_size: Total file size on disk in bytes.
        format_type: Binary format ('PE32', 'PE32+', 'ELF32', 'ELF64', 'Mach-O').

    Returns:
        List of detected anomaly records.
    """
    anomalies: list[dict[str, Any]] = []
    if not sections:
        return anomalies

    ep_found_in_section = False
    ep_section_idx = -1

    for idx, sec in enumerate(sections):
        name = sec.get("name", "")
        v_size = sec.get("virtual_size", sec.get("size", 0))
        r_size = sec.get("raw_size", sec.get("size", 0))
        v_addr = sec.get("virtual_address", 0)
        raw_offset = sec.get("raw_offset", sec.get("offset", 0))
        is_writable = sec.get("is_writable", False)
        is_executable = sec.get("is_executable", False)

        # Parse v_addr if string hex
        if isinstance(v_addr, str):
            try:
                v_addr = int(v_addr, 16)
            except ValueError:
                v_addr = 0

        # Skip mandatory ELF index 0 NULL section
        if idx == 0 and not name and format_type and "ELF" in format_type.upper():
            continue

        # 1. Check for empty or unprintable section names
        if not name or not name.strip():
            anomalies.append(
                {
                    "section": name or "(empty)",
                    "anomaly": "empty_section_name",
                    "severity": "high",
                    "description": f"Section at index {idx} has an empty or whitespace name",
                }
            )
        elif any(ord(c) < 32 or ord(c) > 126 for c in name):
            anomalies.append(
                {
                    "section": name,
                    "anomaly": "unprintable_section_name",
                    "severity": "high",
                    "description": f"Section '{name}' contains non-printable or obfuscated characters",
                }
            )
        else:
            # Check suspicious section name
            name_lower = name.lower()
            if name_lower in _SUSPICIOUS_SECTIONS:
                anomalies.append(
                    {
                        "section": name,
                        "anomaly": "known_packer_section",
                        "severity": "high",
                        "description": f"Section '{name}' matches known packer/protector '{_SUSPICIOUS_SECTIONS[name_lower]}'",
                    }
                )
            elif not is_standard_section_name(name, format_type):
                anomalies.append(
                    {
                        "section": name,
                        "anomaly": "non_standard_section_name",
                        "severity": "low",
                        "description": f"Section '{name}' is non-standard for {format_type}",
                    }
                )

        # 2. W+X violation (Writable and Executable)
        if is_writable and is_executable:
            anomalies.append(
                {
                    "section": name,
                    "anomaly": "writable_and_executable",
                    "severity": "critical",
                    "description": f"Section '{name}' violates W⊕X protection (both Writable and Executable)",
                }
            )

        # 3. VirtualSize vs RawSize disparity
        if r_size == 0 and v_size > 0:
            anomalies.append(
                {
                    "section": name,
                    "anomaly": "zero_raw_size",
                    "severity": "high",
                    "description": f"Section '{name}' has SizeOfRawData=0 but VirtualSize={v_size} (unpacked into memory at runtime)",
                }
            )
        elif r_size > 0 and v_size > (r_size * 3) and v_size > 4096:
            anomalies.append(
                {
                    "section": name,
                    "anomaly": "virtual_raw_size_disparity",
                    "severity": "medium",
                    "description": f"Section '{name}' VirtualSize ({v_size}) is substantially larger than RawSize ({r_size})",
                }
            )

        # 4. Raw offset out of file bounds
        if file_size > 0 and raw_offset > 0 and (raw_offset + r_size) > (file_size + 512):
            anomalies.append(
                {
                    "section": name,
                    "anomaly": "section_raw_out_of_bounds",
                    "severity": "high",
                    "description": f"Section '{name}' raw data extent ({raw_offset + r_size}) extends beyond file size ({file_size})",
                }
            )

        # Check entrypoint inclusion
        if entrypoint is not None and entrypoint > 0:
            sec_len = max(v_size, r_size, 1)
            # Direct VA match
            in_sec = v_addr <= entrypoint < (v_addr + sec_len)
            if not in_sec and entrypoint >= 0x10000:
                # Check RVA against standard image bases
                for base in (0x400000, 0x140000000, 0x10000000, 0x00400000):
                    if entrypoint >= base:
                        ep_rva = entrypoint - base
                        if v_addr <= ep_rva < (v_addr + sec_len):
                            in_sec = True
                            break
                if not in_sec:
                    # Low 20 bits RVA mask
                    rva_masked = entrypoint & 0x000FFFFF
                    if v_addr <= rva_masked < (v_addr + sec_len):
                        in_sec = True

            if in_sec:
                ep_found_in_section = True
                ep_section_idx = idx

    # Entry point anomalies
    if entrypoint is not None and entrypoint > 0 and sections:
        if ep_found_in_section and ep_section_idx >= 0:
            ep_sec = sections[ep_section_idx]
            ep_name = ep_sec.get("name", "")
            ep_ent = ep_sec.get("entropy", 0.0) or 0.0
            ep_rsize = ep_sec.get("raw_size", ep_sec.get("size", 0))
            ep_w = ep_sec.get("is_writable", False)

            # Entrypoint in last section
            if ep_section_idx == len(sections) - 1 and len(sections) > 1:
                anomalies.append(
                    {
                        "section": ep_name,
                        "anomaly": "entrypoint_in_last_section",
                        "severity": "high",
                        "description": f"Entry point (0x{entrypoint:x}) is in the last section '{ep_name}' (common unpacking stub pattern)",
                    }
                )

            # Entrypoint in high-entropy section
            if ep_ent >= 7.0:
                anomalies.append(
                    {
                        "section": ep_name,
                        "anomaly": "entrypoint_in_high_entropy_section",
                        "severity": "high",
                        "description": f"Entry point is in high-entropy section '{ep_name}' (entropy={ep_ent:.2f})",
                    }
                )

            # Entrypoint in writable section
            if ep_w:
                anomalies.append(
                    {
                        "section": ep_name,
                        "anomaly": "entrypoint_in_writable_section",
                        "severity": "high",
                        "description": f"Entry point is in writable section '{ep_name}'",
                    }
                )

            # Entrypoint in section with 0 raw size
            if ep_rsize == 0:
                anomalies.append(
                    {
                        "section": ep_name,
                        "anomaly": "entrypoint_in_zero_raw_section",
                        "severity": "critical",
                        "description": f"Entry point is in section '{ep_name}' which has SizeOfRawData=0",
                    }
                )
        elif not ep_found_in_section and len(sections) > 0:
            # EP outside all sections
            anomalies.append(
                {
                    "section": "(none)",
                    "anomaly": "entrypoint_outside_sections",
                    "severity": "critical",
                    "description": f"Entry point (0x{entrypoint:x}) does not fall within any defined section",
                }
            )

    return anomalies


__all__ = [
    "_STANDARD_ELF_SECTIONS",
    "_STANDARD_MACHO_SECTIONS",
    "_STANDARD_PE_SECTIONS",
    "_SUSPICIOUS_SECTIONS",
    "detect_section_anomalies",
    "is_standard_section_name",
]
