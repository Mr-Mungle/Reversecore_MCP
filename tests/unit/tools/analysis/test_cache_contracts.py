"""Unit tests for cache_tools contracts, dry_run preview, and schema validation."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.result import ToolError, ToolSuccess
from reversecore_mcp.tools.analysis.cache_tools import (
    export_analysis_cache,
    import_analysis_cache,
)


@pytest.fixture
def sample_rcpack():
    return {
        "format": "rcpack",
        "version": "1.0",
        "file_hash": "b" * 64,
        "entries": [
            {
                "function_address": "0x401050",
                "decompiler": "ghidra",
                "status": "success",
                "data": json.dumps(
                    {"status": "success", "data": "int add(int a, int b) { return a + b; }"}
                ),
            }
        ],
    }


@pytest.mark.asyncio
async def test_import_analysis_cache_dry_run_mode(sample_rcpack, tmp_path):
    """Verify dry_run=True validates without writing to SQLite/Redis store."""
    pack_file = tmp_path / "valid.rcpack"
    pack_file.write_text(json.dumps(sample_rcpack), encoding="utf-8")

    with (
        patch("reversecore_mcp.tools.analysis.cache_tools.validate_file_path") as mock_val,
        patch(
            "reversecore_mcp.tools.analysis.cache_tools.import_cache_data",
            new_callable=AsyncMock,
        ) as mock_import,
    ):
        mock_val.return_value = pack_file
        mock_import.return_value = 1

        result = await import_analysis_cache(str(pack_file), dry_run=True)

        assert isinstance(result, ToolSuccess)
        assert result.ok is True
        assert result.metadata["dry_run"] is True
        assert result.metadata["imported_count"] == 1
        assert "Dry run validated" in str(result.data)
        mock_import.assert_awaited_once_with(sample_rcpack, target_file=None, dry_run=True)


@pytest.mark.asyncio
async def test_export_analysis_cache_empty_recovery_hint(tmp_path):
    """Verify CACHE_EXPORT_EMPTY returns actionable recovery guidance."""
    fake_bin = tmp_path / "test.exe"
    fake_bin.write_bytes(b"\x90\x90")

    with (
        patch(
            "reversecore_mcp.tools.analysis.cache_tools.validate_file_path", return_value=fake_bin
        ),
        patch(
            "reversecore_mcp.tools.analysis.cache_tools.calculate_file_sha256",
            return_value="c" * 64,
        ),
        patch(
            "reversecore_mcp.tools.analysis.cache_tools.export_cache_by_hash",
            new_callable=AsyncMock,
            return_value={"entries": []},
        ),
    ):
        result = await export_analysis_cache(str(fake_bin))

        assert isinstance(result, ToolError)
        assert result.ok is False
        assert result.error_code == "CACHE_EXPORT_EMPTY"
        assert result.error is not None
        assert result.error.retryable is False
        assert "r2_decompile" in result.error.recovery_hint


@pytest.mark.asyncio
async def test_import_analysis_cache_missing_file_recovery(tmp_path):
    """Verify missing file returns structured error and hint."""
    missing = tmp_path / "nonexistent.rcpack"
    with patch(
        "reversecore_mcp.tools.analysis.cache_tools.validate_file_path", return_value=missing
    ):
        result = await import_analysis_cache(str(missing))

        assert isinstance(result, ToolError)
        assert result.ok is False
        assert result.error_code == "CACHE_IMPORT_ERROR"
        assert result.error is not None
        assert "list_workspace" in result.error.recovery_hint
