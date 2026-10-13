"""
MCP Tools for Exporting and Importing Decompilation/Analysis Cache.

Enables sharing and portability of expensive analysis operations by exporting
Redis/SQLite cache to a JSON file (.rcpack) and importing it back.
"""

from pathlib import Path
from typing import Annotated

from pydantic import Field

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.analysis_cache import (
    calculate_file_sha256,
    export_cache_by_hash,
    import_cache_data,
)
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)


@log_execution(tool_name="export_analysis_cache")
@track_metrics("export_analysis_cache")
@handle_tool_errors
async def export_analysis_cache(
    file_path: Annotated[
        str,
        Field(
            description="Path to the binary file whose cache should be exported. Must reside within workspace.",
            min_length=1,
        ),
    ],
    output_name: Annotated[
        str | None,
        Field(
            description="Optional custom name for the output file (filename only, e.g. 'sample_cache.rcpack'). Default is '<binary_name>_<hash[:8]>.rcpack'.",
        ),
    ] = None,
) -> ToolResult:
    """Export decompilation cache for a specific binary to a JSON file.

    Extracts cached decompilation results from the SQLite/Redis store
    and saves them as a portable .rcpack file.

    Args:
        file_path: Path to the binary file whose cache should be exported.
        output_name: Optional custom name for the output file. Default is
            `<binary_name>_<hash>.rcpack`.

    Returns:
        ToolResult indicating success or failure, with the export path.
    """
    validated_path = validate_file_path(file_path)
    file_hash = calculate_file_sha256(validated_path)
    if not file_hash:
        return failure(
            "CACHE_EXPORT_ERROR",
            "Could not calculate SHA256 of the binary.",
            recovery_hint="Check if the file is readable and not empty.",
            retryable=False,
        )

    cache_data = await export_cache_by_hash(file_hash)
    entries_count = len(cache_data.get("entries", []))

    if entries_count == 0:
        return failure(
            "CACHE_EXPORT_EMPTY",
            f"No cache entries found for {validated_path.name} (SHA256: {file_hash}).",
            recovery_hint="Run analysis or decompilation on the binary first (e.g. r2_decompile, run_capa, or detect_packer) before exporting cache.",
            retryable=False,
        )

    config = get_config()
    if not output_name:
        output_name = f"{validated_path.name}_{file_hash[:8]}.rcpack"
    else:
        # Sanitize output_name to strictly filename only (prevent path traversal)
        output_name = Path(output_name).name
        if not output_name or output_name in (".", ".."):
            return failure(
                "INVALID_PARAMETER",
                "output_name cannot be empty or relative traversal",
                recovery_hint="Specify a valid base filename such as 'analysis_cache.rcpack'.",
                retryable=False,
            )

    export_path = (config.workspace / output_name).resolve()
    try:
        export_path.relative_to(config.workspace.resolve())
    except ValueError:
        return failure(
            "SECURITY_ERROR",
            "Export path is outside allowed workspace directory",
            recovery_hint="Do not use paths that escape the workspace directory.",
            retryable=False,
        )

    try:
        with open(export_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(cache_data, indent=2))
    except Exception as e:
        logger.error(f"Failed to write cache export file: {e}")
        return failure(
            "CACHE_EXPORT_ERROR",
            f"Failed to write export file: {e}",
            recovery_hint="Check workspace disk write permissions and available free space.",
            retryable=True,
        )

    logger.info(f"Exported {entries_count} cache entries to {export_path}")
    return success(
        f"Exported {entries_count} cache entries.",
        export_path=str(export_path),
        entries_count=entries_count,
        file_hash=file_hash,
    )


@log_execution(tool_name="import_analysis_cache")
@track_metrics("import_analysis_cache")
@handle_tool_errors
async def import_analysis_cache(
    pack_path: Annotated[
        str,
        Field(
            description="Path to the .rcpack JSON cache pack file to import. Must reside within workspace.",
            min_length=1,
        ),
    ],
    target_file_path: Annotated[
        str | None,
        Field(
            description="Optional path to local binary file to verify against the pack's declared SHA256 before importing.",
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        Field(
            description="If True, validates the cache pack format, entry count, and target hash without writing to SQLite/Redis store.",
        ),
    ] = False,
) -> ToolResult:
    """Import a decompilation cache from a portable .rcpack JSON file.

    Loads validated external results into the SQLite/Redis store. Imported
    results keep external provenance. If target_file_path is provided, its
    SHA256 must match the pack's declared binary hash.

    Args:
        pack_path: Path to the .rcpack file.
        target_file_path: Optional binary whose SHA256 must match the pack.
        dry_run: If True, validate integrity without persisting to cache stores.

    Returns:
        ToolResult indicating success or failure, with the number of imported entries.
    """
    validated_path = validate_file_path(pack_path)

    if not validated_path.exists():
        return failure(
            "CACHE_IMPORT_ERROR",
            f"File not found: {pack_path}",
            recovery_hint="Check workspace file listings with list_workspace.",
            retryable=False,
        )

    try:
        with open(validated_path, encoding="utf-8") as f:
            cache_data = json.loads(f.read())
    except Exception as e:
        logger.error(f"Failed to read or parse cache import file: {e}")
        return failure(
            "CACHE_IMPORT_ERROR",
            f"Failed to parse export file: {e}",
            recovery_hint="Verify that the file is well-formed JSON and readable.",
            retryable=False,
        )

    if not isinstance(cache_data, dict):
        return failure(
            "CACHE_IMPORT_INVALID",
            "Invalid cache pack. Expected a JSON object.",
            recovery_hint="Provide a valid .rcpack JSON generated by export_analysis_cache.",
            retryable=False,
        )

    if cache_data.get("format") != "rcpack":
        return failure(
            "CACHE_IMPORT_INVALID",
            "Invalid cache format. Expected 'rcpack'.",
            recovery_hint="The pack must have 'format': 'rcpack' in its root JSON object.",
            retryable=False,
        )

    target_file = None
    if target_file_path is not None:
        try:
            target_file = validate_file_path(target_file_path, read_only=True)
        except Exception as e:
            return failure(
                "CACHE_IMPORT_TARGET_INVALID",
                f"Invalid target file: {e}",
                recovery_hint="Ensure target_file_path resolves within the authorized workspace.",
                retryable=False,
            )

    try:
        if dry_run:
            imported_count = await import_cache_data(
                cache_data, target_file=target_file, dry_run=True
            )
        else:
            imported_count = await import_cache_data(cache_data, target_file=target_file)
    except ValueError as e:
        return failure(
            "CACHE_IMPORT_INVALID",
            str(e),
            recovery_hint="Inspect the .rcpack file structure or ensure the binary hash matches.",
            retryable=False,
        )

    if imported_count == 0:
        return failure(
            "CACHE_IMPORT_EMPTY",
            "No valid entries were found or imported.",
            recovery_hint="The .rcpack file contains no decompilation entries to import.",
            retryable=False,
        )

    file_hash = cache_data.get("file_hash", "Unknown")
    action_label = "Dry run validated" if dry_run else "Successfully imported"
    logger.info(f"{action_label} {imported_count} cache entries for hash {file_hash}")
    return success(
        f"{action_label} {imported_count} cache entries.",
        imported_count=imported_count,
        file_hash=file_hash,
        target_hash_verified=target_file is not None,
        dry_run=dry_run,
    )
