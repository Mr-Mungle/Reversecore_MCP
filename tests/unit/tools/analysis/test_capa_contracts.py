"""Unit tests for capa_tools response contracts, format enums, and structured errors."""

from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.core.result import ToolError, ToolSuccess
from reversecore_mcp.tools.analysis.capa_tools import (
    CapaOutputFormat,
    run_capa,
    run_capa_quick,
)


@pytest.mark.asyncio
async def test_run_capa_invalid_output_format():
    """Verify invalid output_format returns structured VALIDATION_ERROR."""
    result = await run_capa("/path/to/binary", output_format="unsupported_format")
    assert isinstance(result, ToolError)
    assert result.ok is False
    assert result.error_code == "VALIDATION_ERROR"
    assert result.error is not None
    assert result.error.retryable is False
    assert "summary" in result.error.recovery_hint


@pytest.mark.asyncio
async def test_run_capa_detailed_format(tmp_path):
    """Verify detailed format includes match locations and rule metadata."""
    import sys

    fake_bin = tmp_path / "sample.exe"
    fake_bin.write_bytes(b"\x90" * 100)

    mock_capa = MagicMock()
    mock_loader = MagicMock()
    mock_main = MagicMock()
    mock_rules = MagicMock()

    mock_capa.loader = mock_loader
    mock_capa.main = mock_main
    mock_capa.rules = mock_rules

    mock_main.get_default_root.return_value = "/mock/rules"
    mock_main.BACKEND_VIV = "vivisect"

    mock_rule = MagicMock()
    mock_rule.meta = {
        "namespace": "anti-analysis/anti-debugging",
        "description": "Check for debugger present",
        "scope": "function",
        "authors": ["flare-team"],
        "examples": ["sample.exe"],
    }

    mock_rules.get_rules.return_value = ({"anti_dbg": mock_rule}, None)
    mock_main.find_capabilities.return_value = ({"anti_dbg": [0x401000]}, {})

    with (
        patch("reversecore_mcp.tools.analysis.capa_tools._is_capa_available", return_value=True),
        patch(
            "reversecore_mcp.tools.analysis.capa_tools.validate_file_path", return_value=fake_bin
        ),
        patch.dict(
            sys.modules,
            {
                "capa": mock_capa,
                "capa.loader": mock_loader,
                "capa.main": mock_main,
                "capa.rules": mock_rules,
            },
        ),
    ):
        result = await run_capa(str(fake_bin), output_format=CapaOutputFormat.DETAILED)
        assert isinstance(result, ToolSuccess)
        assert result.ok is True
        assert len(result.data["capabilities"]) == 1
        cap = result.data["capabilities"][0]
        assert cap["name"] == "anti_dbg"
        assert cap["matches"] == ["0x401000"]
        assert cap["authors"] == ["flare-team"]
        assert cap["examples"] == ["sample.exe"]


@pytest.mark.asyncio
async def test_run_capa_quick_filtering(tmp_path):
    """Verify run_capa_quick returns only high-risk capabilities."""
    import sys

    fake_bin = tmp_path / "sample.exe"
    fake_bin.write_bytes(b"\x90" * 100)

    mock_capa = MagicMock()
    mock_loader = MagicMock()
    mock_main = MagicMock()
    mock_rules = MagicMock()

    mock_capa.loader = mock_loader
    mock_capa.main = mock_main
    mock_capa.rules = mock_rules

    mock_main.get_default_root.return_value = "/mock/rules"
    mock_main.BACKEND_VIV = "vivisect"

    rule_high = MagicMock()
    rule_high.meta = {
        "namespace": "defense-evasion",
        "description": "Bypass AV",
        "scope": "function",
    }
    rule_benign = MagicMock()
    rule_benign.meta = {
        "namespace": "file-system",
        "description": "Read file",
        "scope": "function",
    }

    mock_rules.get_rules.return_value = ({"bypass": rule_high, "read": rule_benign}, None)
    mock_main.find_capabilities.return_value = ({"bypass": ["m1"], "read": ["m2"]}, {})

    with (
        patch("reversecore_mcp.tools.analysis.capa_tools._is_capa_available", return_value=True),
        patch(
            "reversecore_mcp.tools.analysis.capa_tools.validate_file_path", return_value=fake_bin
        ),
        patch.dict(
            sys.modules,
            {
                "capa": mock_capa,
                "capa.loader": mock_loader,
                "capa.main": mock_main,
                "capa.rules": mock_rules,
            },
        ),
    ):
        result = await run_capa_quick(str(fake_bin))
        assert isinstance(result, ToolSuccess)
        assert result.ok is True
        assert result.data["total_filtered"] == 1
        assert result.data["high_risk_capabilities"][0]["name"] == "bypass"
