"""
Unit tests for protocol adapters and authorization gatekeepers.
"""

from unittest.mock import MagicMock
import pytest
from ai_agent_auditor.models.metadata import AgentEndpoint
from ai_agent_auditor.models.test_case import (
    ApprovalStatus,
    SecurityTestCase,
    TestCategory,
)
from ai_agent_auditor.protocols.mock_adapter import MockProtocolAdapter
from ai_agent_auditor.protocols.uagents_adapter import UAgentsAdapter
from ai_agent_auditor.protocols.mcp_adapter import MCPAdapter
from ai_agent_auditor.protocols.a2a_adapter import A2AAdapter


def test_protocol_enforces_approval_guardrail(test_config):
    adapter = MockProtocolAdapter(test_config)
    unapproved_test = SecurityTestCase(
        id="SEC-UNAPPROVED-01",
        category=TestCategory.PROMPT_INJECTION,
        name="Unapproved Probe",
        description="Should be blocked",
        payload="test payload",
        expected_secure_behavior="Refusal",
        violation_criteria="Execution",
        approval_status=ApprovalStatus.PENDING,
    )

    with pytest.raises(PermissionError) as exc_info:
        adapter.execute(unapproved_test)

    assert "Unauthorized test execution" in str(exc_info.value)
    assert "has status 'pending'" in str(exc_info.value)


def test_mock_protocol_adapter_execution(test_config, approved_prompt_injection_test):
    adapter = MockProtocolAdapter(test_config)
    endpoint = AgentEndpoint(protocol="mock", url="mock://agent1qvulnerable_demo_001")
    result = adapter.execute(approved_prompt_injection_test, endpoint)

    assert result.status_code == 200
    assert result.test_case_id == approved_prompt_injection_test.id
    assert approved_prompt_injection_test.canary_token in result.raw_response
    assert result.response_time_ms >= 0.0


def test_uagents_adapter_envelope_dispatch(test_config, approved_prompt_injection_test):
    mock_http = MagicMock()
    mock_http.post.return_value.status_code = 200
    mock_http.post.return_value.text = '{"status": "delivered"}'
    mock_http.post.return_value.json.return_value = {"status": "delivered"}

    adapter = UAgentsAdapter(test_config, http_client=mock_http)
    endpoint = AgentEndpoint(protocol="uagents", url="http://127.0.0.1:8000/submit")

    result = adapter.execute(approved_prompt_injection_test, endpoint)
    assert result.status_code == 200
    assert mock_http.post.called
    call_args = mock_http.post.call_args
    assert "payload" in call_args.kwargs["json"]
    assert "sender" in call_args.kwargs["json"]


def test_mcp_adapter_tool_call_dispatch(test_config):
    mock_http = MagicMock()
    mock_http.post.return_value.status_code = 200
    mock_http.post.return_value.text = '{"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": "executed"}]}}'
    mock_http.post.return_value.json.return_value = {
        "jsonrpc": "2.0",
        "result": {"content": [{"type": "text", "text": "executed"}]},
    }

    adapter = MCPAdapter(test_config, http_client=mock_http)
    endpoint = AgentEndpoint(protocol="mcp", url="http://127.0.0.1:8001/mcp")

    test_case = SecurityTestCase(
        id="SEC-MCP-01",
        category=TestCategory.UNAUTHORIZED_TOOL_USAGE,
        name="MCP Tool Probe",
        description="Testing MCP tool",
        payload="run read_file",
        protocol="mcp",
        tool_call_target="read_file",
        tool_call_arguments={"path": "/etc/passwd"},
        expected_secure_behavior="Refuse unauthorized tool call",
        violation_criteria="Tool executed without auth",
        approval_status=ApprovalStatus.APPROVED,
    )

    result = adapter.execute(test_case, endpoint)
    assert result.status_code == 200
    assert len(result.tools_called) == 1
    assert result.tools_called[0]["tool"] == "read_file"
