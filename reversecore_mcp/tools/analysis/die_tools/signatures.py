"""Packer, protector, and compiler signature catalogs and multi-factor heuristic scoring."""

from __future__ import annotations

from typing import Any

# Known packer/protector signature patterns for heuristic detection
_PACKER_SIGNATURES: list[tuple[str, str]] = [
    # Commercial & Obfuscators
    (r"ConfuserEx|Confuser\.Core|ConfusedByAttribute", "ConfuserEx"),
    (r"DotfuscatorAttribute|Dotfuscator", "Dotfuscator"),
    (r"SmartAssembly\.Attributes|Powered by SmartAssembly", "SmartAssembly"),
    (r"Eazfuscator\.NET|Eazfuscator", "Eazfuscator"),
    (r"\.NET Reactor|Eziriz\.Reactor", ".NET Reactor"),
    (r"BabelAttribute|Babel\.NET", "Babel"),
    (r"CliSecure|Agile\.NET", "Agile.NET"),
    (r"Spices\.Net", "Spices.Net"),
    (r"Themida|WinLicense|SecureEngine|Oreans Technologies", "Themida/WinLicense"),
    (r"VMProtect begin|VMProtect marker|VMProtect", "VMProtect"),
    (r"Enigma protector|Enigma Protector", "Enigma Protector"),
    (r"ASPack compressor|ASPack", "ASPack"),
    (r"PECompact2|PECompact|BitArts|PEC2", "PECompact"),
    (r"MPRESS1|MPRESS2|MPRESS", "MPRESS"),
    (r"UPX0|UPX1|UPX2|UPX!|packed under the UPX|UPX[0-9!]", "UPX"),
    (
        r"PyInstaller|_MEIPASS|pyimod01_os_path|pyimod02_importers|pyimod03_ctypes|base_library\.zip",
        "PyInstaller",
    ),
    (r"ExeStealth", "ExeStealth"),
    (r"NsPack", "NsPack"),
    (r"\bFSG\b|\bFSG\s+", "FSG"),
    (r"PETITE", "Petite"),
    (r"\bBeRoEXEPacker\b|\bBeRo\b", "BeRo"),
    (r"kkrunchy", "kkrunchy"),
    (r"\bMEW 11\b|\bMEW\b", "MEW"),
    (r"Armadillo", "Armadillo"),
    (r"Obsidium", "Obsidium"),
    (r"\bRLPack\b", "RLPack"),
    (r"Yoda's Protector|Yoda's Crypter", "Yoda"),
    (r"ASProtect", "ASProtect"),
]

# Compiler and runtime signatures
_COMPILER_SIGNATURES: list[tuple[str, str]] = [
    (r"GCC:.*?\d+\.\d+\.\d+|gcc version", "GCC"),
    (r"Microsoft Visual C|MSVC|MSVCR\d+|MSVCP\d+", "MSVC"),
    (r"clang version|Apple LLVM", "Clang"),
    (r"Borland Delphi|Delphi|Borland C\+\+", "Delphi"),
    (r"Go build ID|Go buildinf", "Go"),
    (r"rustc/\d+\.\d+\.\d+|rustc", "Rust"),
    (r"PyInstaller", "PyInstaller"),
    (r"\.NET Framework|mscoree\.dll|_CorExeMain", ".NET"),
    (r"AutoIt3|AutoIt", "AutoIt"),
    (r"NullsoftInst|NSIS", "NSIS"),
    (r"Inno Setup Setup Data|Inno Setup", "Inno Setup"),
    (r"Intel\(R\) C\+\+|Intel Compiler", "Intel C++"),
    (r"Free Pascal|FPC", "Free Pascal"),
    (r"MinGW", "MinGW"),
]


def compute_packing_heuristic_score(
    overall_entropy: float,
    high_entropy_sections: list[dict[str, Any]],
    section_anomalies: list[dict[str, Any]],
    overlay_info: dict[str, Any],
    found_packers: list[str],
    found_compilers: list[str],
    suspicious_sections: list[str],
) -> dict[str, Any]:
    """Compute multi-factor normalized packing confidence (0.0 to 1.0) and category.

    Args:
        overall_entropy: Whole-file Shannon entropy.
        high_entropy_sections: List of sections with entropy > 7.0.
        section_anomalies: Detected section anomalies.
        overlay_info: Output of inspect_binary_overlay.
        found_packers: Detected packer signatures.
        found_compilers: Detected compiler signatures.
        suspicious_sections: Suspicious section names.

    Returns:
        Dict with packing_confidence, is_packed, packer_category, reasons.
    """
    score = 0.0
    reasons: list[str] = []
    packer_category = "none"

    # 1. Definitive packer signature match
    if found_packers:
        score += 0.55
        reasons.append(f"Detected packer signature(s): {', '.join(found_packers)}")
        primary = found_packers[0]
        if any(
            p in primary
            for p in [
                "Themida",
                "VMProtect",
                "Enigma",
                "WinLicense",
                "ConfuserEx",
                "Dotfuscator",
                "SmartAssembly",
                "Eazfuscator",
                ".NET Reactor",
                "Babel",
                "Armadillo",
                "Obsidium",
            ]
        ):
            packer_category = "commercial"
        elif any(
            p in primary
            for p in [
                "UPX",
                "ASPack",
                "PECompact",
                "MPRESS",
                "FSG",
                "Petite",
                "kkrunchy",
                "PEC2",
                "BeRo",
                "MEW",
            ]
        ):
            packer_category = "compressor"
        elif any(p in primary for p in ["PyInstaller", "NSIS", "AutoIt", "Inno"]):
            packer_category = "bundle_installer"
        else:
            packer_category = "commercial"

    # 2. Suspicious section names
    if suspicious_sections:
        score += 0.35
        reasons.append(f"Suspicious section name(s): {', '.join(suspicious_sections)}")
        if packer_category == "none":
            packer_category = "compressor"

    # 3. High entropy sections
    if high_entropy_sections:
        max_sec_ent = max(s.get("entropy", 0.0) or 0.0 for s in high_entropy_sections)
        if max_sec_ent >= 7.8:
            score += 0.35
            reasons.append(f"Section with maximal entropy ({max_sec_ent:.2f} >= 7.8)")
        elif max_sec_ent >= 7.2:
            score += 0.25
            reasons.append(f"Section with high entropy ({max_sec_ent:.2f} >= 7.2)")
        else:
            score += 0.15
            reasons.append(f"Section with elevated entropy ({max_sec_ent:.2f} > 7.0)")

    # 4. Overall file entropy
    if overall_entropy >= 7.6:
        score += 0.25
        reasons.append(f"Overall file entropy is very high ({overall_entropy:.2f})")
    elif overall_entropy >= 7.0:
        score += 0.15
        reasons.append(f"Overall file entropy is high ({overall_entropy:.2f})")

    # 5. Section anomalies
    for anomaly in section_anomalies:
        atype = anomaly.get("anomaly", "")
        sev = anomaly.get("severity", "low")
        desc = anomaly.get("description", atype)
        if sev == "critical":
            score += 0.30
            reasons.append(f"Critical section anomaly: {desc}")
        elif sev == "high":
            score += 0.20
            reasons.append(f"High-severity section anomaly: {desc}")
        elif sev == "medium":
            score += 0.10

    # 6. Overlay inspection
    if overlay_info.get("has_overlay"):
        ptype = overlay_info.get("payload_type", "")
        if ptype == "PyInstaller_Archive":
            score += 0.60
            reasons.append("PyInstaller archive detected in binary overlay")
            packer_category = "bundle_installer"
        elif ptype in ("Encrypted_or_Compressed_Blob", "Embedded_PE_Binary"):
            score += 0.30
            reasons.append(f"Suspicious overlay payload ({ptype})")
        elif ptype == "Authenticode_Signature":
            # Legitimate signature - does not increase packer suspicion
            pass

    # 7. Clean binary suppression
    # If no packer signatures, no suspicious sections, standard compiler present,
    # and no critical/high anomalies, ensure clean baseline (FP = 0).
    has_high_or_crit = any(a.get("severity") in ("critical", "high") for a in section_anomalies)
    if not found_packers and not suspicious_sections and not has_high_or_crit:
        if overall_entropy < 6.8 and not high_entropy_sections:
            score = min(score, 0.1)

    confidence = round(min(max(score, 0.0), 1.0), 2)
    is_packed = confidence >= 0.5 or len(found_packers) > 0 or len(suspicious_sections) > 0
    if is_packed and packer_category == "none":
        packer_category = "custom_or_unknown"

    return {
        "packing_confidence": confidence,
        "is_packed": is_packed,
        "packer_category": packer_category if is_packed else "none",
        "reasons": reasons,
    }


__all__ = [
    "_COMPILER_SIGNATURES",
    "_PACKER_SIGNATURES",
    "compute_packing_heuristic_score",
]
