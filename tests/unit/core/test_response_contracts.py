"""Unit tests for response contracts, ErrorInfo, and envelope serialization."""

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.result import (
    ErrorInfo,
    PaginationMeta,
    ToolError,
    failure,
    success,
)


class TestResponseContractSuccess:
    """Verify ToolSuccess fulfills the unified response contract."""

    def test_basic_success_envelope(self):
        res = success(data={"status_check": "ok"}, metric=100)
        assert res.ok is True
        assert res.status == "success"
        assert res.data == {"status_check": "ok"}
        assert res.metadata == {"metric": 100}
        assert res.error is None
        assert res.warnings == []

    def test_success_with_warnings_and_meta(self):
        res = success(
            data=["binary_1", "binary_2"],
            warnings=["Deprecation notice: format x will change in v3"],
            meta={"execution_environment": "test_sandbox"},
            author="tester",
        )
        assert res.ok is True
        assert res.warnings == ["Deprecation notice: format x will change in v3"]
        assert res.meta == {"execution_environment": "test_sandbox", "author": "tester"}

    def test_success_with_pagination(self):
        pag = PaginationMeta(
            page=1,
            page_size=50,
            total_items=120,
            has_more=True,
            next_cursor="cursor_50",
        )
        res = success(data=["item1"], pagination=pag)
        assert res.ok is True
        assert res.pagination is not None
        assert res.pagination.has_more is True
        assert res.pagination.next_cursor == "cursor_50"

    def test_json_serialization_contract(self):
        res = success(data={"key": "val"}, warnings=["info note"], task_id="task-123")
        dump = res.model_dump()
        serialized = json.dumps(dump)
        loaded = json.loads(serialized)

        assert loaded["ok"] is True
        assert loaded["status"] == "success"
        assert loaded["data"] == {"key": "val"}
        assert loaded["warnings"] == ["info note"]
        assert loaded["error"] is None
        assert loaded["metadata"] == {"task_id": "task-123"}


class TestResponseContractError:
    """Verify ToolError fulfills the unified response contract."""

    def test_failure_helper_envelope(self):
        err = failure(
            error_code="DEPENDENCY_UNAVAILABLE",
            message="Required binary radare2 is not found in PATH",
            retryable=False,
            recovery_hint="Install radare2 or run inside official Docker image",
            component="radare2",
        )
        assert err.ok is False
        assert err.status == "error"
        assert err.error_code == "DEPENDENCY_UNAVAILABLE"
        assert err.message == "Required binary radare2 is not found in PATH"
        assert err.error is not None
        assert isinstance(err.error, ErrorInfo)
        assert err.error.code == "DEPENDENCY_UNAVAILABLE"
        assert err.error.message == "Required binary radare2 is not found in PATH"
        assert err.error.retryable is False
        assert err.error.recovery_hint == "Install radare2 or run inside official Docker image"
        assert err.details == {"component": "radare2"}

    def test_retryable_failure_contract(self):
        err = failure(
            error_code="ANALYSIS_TIMEOUT",
            message="Decompilation timed out after 30 seconds",
            retryable=True,
            recovery_hint="Retry with a higher timeout or restrict target_functions",
        )
        assert err.ok is False
        assert err.error is not None
        assert err.error.retryable is True
        assert "target_functions" in err.error.recovery_hint

    def test_direct_tool_error_validator(self):
        err = ToolError(
            error_code="FILE_NOT_FOUND",
            message="File sample.bin was not found",
            hint="Check list_workspace",
        )
        assert err.ok is False
        assert err.error is not None
        assert err.error.code == "FILE_NOT_FOUND"
        assert err.error.message == "File sample.bin was not found"
        assert err.error.recovery_hint == "Check list_workspace"
        assert err.error.retryable is False

    def test_json_serialization_contract(self):
        err = failure(
            error_code="VALIDATION_ERROR",
            message="Invalid parameters",
            retryable=False,
            recovery_hint="Provide a valid hex string",
        )
        dump = err.model_dump()
        serialized = json.dumps(dump)
        loaded = json.loads(serialized)

        assert loaded["ok"] is False
        assert loaded["status"] == "error"
        assert loaded["error"]["code"] == "VALIDATION_ERROR"
        assert loaded["error"]["message"] == "Invalid parameters"
        assert loaded["error"]["retryable"] is False
        assert loaded["error"]["recovery_hint"] == "Provide a valid hex string"
