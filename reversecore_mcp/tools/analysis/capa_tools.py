"""
CAPA integration for capability detection.

CAPA (by Mandiant FLARE) identifies capabilities in executable files,
providing high-level behavioral information like encryption, file deletion, etc.
"""

import asyncio
from enum import Enum
from typing import Annotated, Any

from pydantic import Field

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.next_tool_hints import build_capa_hints, finalize_hints
from reversecore_mcp.core.resilience import circuit_breaker
from reversecore_mcp.core.result import ToolResult, ToolSuccess, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)


class CapaOutputFormat(str, Enum):
    """Output format detail level for CAPA capability detection."""

    SUMMARY = "summary"
    DETAILED = "detailed"
    JSON = "json"


def _is_capa_available() -> bool:
    """Check if CAPA library is available."""
    try:
        import capa  # noqa: F401

        return True
    except ImportError:
        return False


@log_execution()
@circuit_breaker(tool_name="capa", failure_threshold=3, recovery_timeout=45)
async def run_capa(
    file_path: Annotated[
        str,
        Field(
            description="Path to the binary file to analyze (supports PE, ELF, Mach-O, shellcode). Must reside within the allowed workspace.",
            min_length=1,
        ),
    ],
    output_format: Annotated[
        CapaOutputFormat,
        Field(
            description="Output detail level: 'summary' for high-level capability list & MITRE ATT&CK techniques, 'detailed' for expanded rule-level context & MBC mappings, or 'json' for raw structured CAPA output.",
        ),
    ] = CapaOutputFormat.SUMMARY,
) -> ToolResult:
    """Analyze binary capabilities using CAPA (Mandiant FLARE).

    CAPA identifies capabilities in executable files and provides high-level
    behavioral information such as:
    - "encrypt data using AES"
    - "delete files"
    - "communicate via HTTP"
    - "create persistence via registry"

    Supported binary formats: PE, ELF, Mach-O, and raw shellcode.
    Analysis engine: Mandiant CAPA with vivisect backend.
    Execution behavior: Disassembly of functions can be CPU-intensive on binaries >50MB.

    Args:
        file_path: Path to the binary file to analyze within workspace.
        output_format: Output format - 'summary' (default), 'detailed', or 'json'.

    Returns:
        ToolResult with capability analysis, MITRE ATT&CK mappings, and diagnostic hints.
    """
    fmt_val = (
        output_format.value
        if isinstance(output_format, CapaOutputFormat)
        else str(output_format).lower()
    )
    if fmt_val not in ("summary", "detailed", "json"):
        return failure(
            error_code="VALIDATION_ERROR",
            message=f"Invalid output_format '{output_format}'. Supported formats: 'summary', 'detailed', 'json'.",
            hint="Use one of: summary, detailed, json",
            retryable=False,
            recovery_hint="Specify output_format as 'summary' (compact reasoning), 'detailed' (full rules & ATT&CK), or 'json' (raw dump).",
        )

    try:
        validated_path = validate_file_path(file_path)
    except Exception as val_err:
        return failure(
            error_code="VALIDATION_ERROR",
            message=f"File validation failed: {val_err}",
            hint="Ensure file_path resolves within the authorized workspace directory.",
            retryable=False,
            recovery_hint="Ensure the path does not escape the workspace directory.",
        )

    if not _is_capa_available():
        return failure(
            error_code="CAPA_NOT_INSTALLED",
            message="CAPA is not installed. Install with: pip install flare-capa",
            hint="Install flare-capa or run the server inside the official container environment.",
            retryable=False,
            recovery_hint="Install flare-capa via 'pip install flare-capa' or launch the official Docker image.",
            details={"dependency": "flare-capa", "standard_code": "DEPENDENCY_UNAVAILABLE"},
        )

    try:
        import capa.loader
        import capa.main
        import capa.rules

        # Get default rules path
        rules_path = capa.main.get_default_root()

        # Load rules
        try:
            rules, _ = capa.rules.get_rules([rules_path])
        except Exception as e:
            # Falls back to no rules if default path fails
            logger.warning(f"Failed to load CAPA rules: {e}")
            return failure(
                error_code="CAPA_RULES_LOAD_FAILED",
                message=f"Failed to load CAPA rules. Run: capa --update-rules\nError: {e}",
            )

        # Analyze the file
        try:
            extractor = capa.loader.get_extractor(
                str(validated_path),
                "auto",  # Auto-detect format
                capa.main.BACKEND_VIV,  # Use vivisect backend
                [],  # No signatures
                False,  # Disable progress
            )
        except Exception as e:
            logger.error(f"CAPA failed to load file: {e}")
            return failure(
                error_code="CAPA_LOAD_FILE_FAILED",
                message=f"CAPA cannot analyze this file: {e}",
            )

        # Get capabilities asynchronously to prevent event loop blocking
        capabilities, counts = await asyncio.to_thread(
            capa.main.find_capabilities, rules, extractor
        )

        # Format results
        result: dict[str, Any] = {
            "capabilities": [],
            "mitre_attack": [],
            "mbc": [],
            "summary": {
                "total_capabilities": len(capabilities),
                "namespaces": {},
            },
        }

        for rule_name, matches in capabilities.items():
            rule = rules[rule_name]

            capability: dict[str, Any] = {
                "name": rule_name,
                "namespace": rule.meta.get("namespace", ""),
                "description": rule.meta.get("description", ""),
                "scope": rule.meta.get("scope", "function"),
                "match_count": len(matches),
            }

            if fmt_val == "detailed":
                locations = []
                for m in matches:
                    if hasattr(m, "address"):
                        locations.append(hex(m.address))
                    elif isinstance(m, int):
                        locations.append(hex(m))
                    else:
                        locations.append(str(m))
                capability["matches"] = locations
                if "authors" in rule.meta:
                    capability["authors"] = rule.meta["authors"]
                if "examples" in rule.meta:
                    capability["examples"] = rule.meta["examples"]

            # Extract MITRE ATT&CK
            if "att&ck" in rule.meta:
                for attack in rule.meta["att&ck"]:
                    if attack not in result["mitre_attack"]:
                        result["mitre_attack"].append(attack)

            # Extract MBC (Malware Behavior Catalog)
            if "mbc" in rule.meta:
                for mbc in rule.meta["mbc"]:
                    if mbc not in result["mbc"]:
                        result["mbc"].append(mbc)

            result["capabilities"].append(capability)

            # Count by namespace
            ns = capability["namespace"]
            result["summary"]["namespaces"][ns] = result["summary"]["namespaces"].get(ns, 0) + 1

        # Create summary message
        high_risk_namespaces = [
            "anti-analysis",
            "collection",
            "command-and-control",
            "defense-evasion",
            "execution",
            "exfiltration",
            "impact",
            "persistence",
        ]

        high_risk_count = 0
        for ns_name, count in result["summary"]["namespaces"].items():
            if any(ns_name.startswith(hr_ns) or hr_ns in ns_name for hr_ns in high_risk_namespaces):
                high_risk_count += count

        message = f"Detected {len(capabilities)} capabilities"
        if high_risk_count > 0:
            message += f" ({high_risk_count} high-risk)"
        if result["mitre_attack"]:
            message += f", {len(result['mitre_attack'])} MITRE ATT&CK techniques"

        # ------------------------------------------------------------------
        # scan_diagnostics: lets callers distinguish 'no capabilities'
        # (genuine clean binary) from 'tool error' or 'format unsupported'
        # ------------------------------------------------------------------
        result["scan_diagnostics"] = {
            "capabilities_found": len(capabilities),
            "high_risk_count": high_risk_count,
            "mitre_techniques_found": len(result["mitre_attack"]),
            "mbc_behaviors_found": len(result.get("mbc", [])),
            "empty_reason": (
                "CAPA found no capabilities. Possible causes: "
                "(1) binary is genuinely simple/benign, "
                "(2) binary is packed/obfuscated (unpack first), "
                "(3) CAPA rules do not cover this binary's framework/language, "
                "(4) binary type not fully supported by CAPA (e.g. Go, Rust binaries)."
                if not capabilities
                else None
            ),
        }

        # Build adaptive next-tool hints based on detected capabilities
        cap_names = [
            c["name"] for c in result.get("capabilities", []) if isinstance(c, dict) and "name" in c
        ]
        _hints = finalize_hints(build_capa_hints(file_path, cap_names))

        return success(
            data=result,
            hints=_hints or None,
            message=message,
            high_risk_count=high_risk_count,
            mitre_count=len(result["mitre_attack"]),
        )

    except Exception as e:
        logger.error(f"CAPA analysis failed: {e}")
        return failure(error_code="CAPA_ANALYSIS_FAILED", message=f"CAPA analysis failed: {e}")


@log_execution()
async def run_capa_quick(
    file_path: Annotated[
        str,
        Field(
            description="Path to the binary file to analyze (supports PE, ELF, Mach-O, shellcode). Must reside within workspace.",
            min_length=1,
        ),
    ],
) -> ToolResult:
    """Quick CAPA scan returning only high-risk capabilities.

    Faster than full run_capa, focuses on:
    - Anti-analysis techniques
    - Persistence mechanisms
    - C2 communication
    - Data exfiltration
    - Impact capabilities

    Args:
        file_path: Path to the binary file

    Returns:
        ToolResult with high-risk capabilities only
    """
    result = await run_capa(file_path)

    if not isinstance(result, ToolSuccess):
        return result

    # Filter to high-risk only
    high_risk_namespaces = {
        "anti-analysis",
        "collection",
        "command-and-control",
        "defense-evasion",
        "execution",
        "exfiltration",
        "impact",
        "persistence",
    }

    filtered_caps = [
        cap
        for cap in result.data["capabilities"]
        if any(ns in cap["namespace"] for ns in high_risk_namespaces)
    ]

    return success(
        data={
            "high_risk_capabilities": filtered_caps,
            "mitre_attack": result.data["mitre_attack"],
            "total_filtered": len(filtered_caps),
        },
        message=f"{len(filtered_caps)} high-risk capabilities detected",
    )
