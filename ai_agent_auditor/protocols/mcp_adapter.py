"""
Model Context Protocol (MCP) Adapter.
"""

import json
import logging
from typing import Any, Dict, Optional
import httpx
from ai_agent_auditor.config import AuditorConfig
from ai_agent_auditor.models.metadata import AgentEndpoint
from ai_agent_auditor.models.result import ExecutionResult
from ai_agent_auditor.models.test_case import SecurityTestCase
from ai_agent_auditor.protocols.base import BaseProtocolAdapter

logger = logging.getLogger(__name__)


class MCPAdapter(BaseProtocolAdapter):
    """Adapter for interacting with MCP-compliant servers via JSON-RPC 2.0."""

    def __init__(self, config: AuditorConfig, http_client: Optional[httpx.Client] = None):
        super().__init__(config)
        self.http_client = http_client or httpx.Client(timeout=config.request_timeout_seconds)

    def _send_payload(
        self,
        test_case: SecurityTestCase,
        endpoint: Optional[AgentEndpoint],
    ) -> ExecutionResult:
        if not endpoint or not endpoint.url:
            raise ValueError("Endpoint URL required for MCP communication.")

        url = endpoint.url

        # Build MCP JSON-RPC 2.0 message
        if test_case.tool_call_target:
            rpc_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": test_case.tool_call_target,
                    "arguments": test_case.tool_call_arguments or {},
                },
            }
        else:
            rpc_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "sampling/createMessage",
                "params": {
                    "messages": [
                        {
                            "role": "user",
                            "content": {"type": "text", "text": test_case.payload},
                        }
                    ]
                },
            }

        tools_called = []
        try:
            response = self.http_client.post(
                url,
                json=rpc_payload,
                headers={"Content-Type": "application/json", "User-Agent": "AI-Agent-Auditor/1.0"},
            )
            raw_text = response.text
            parsed = None
            try:
                parsed = response.json()
                if "result" in parsed and test_case.tool_call_target:
                    tools_called.append({
                        "tool": test_case.tool_call_target,
                        "arguments": test_case.tool_call_arguments,
                        "result": parsed["result"],
                    })
            except Exception:
                pass

            return ExecutionResult(
                test_case_id=test_case.id,
                protocol="mcp",
                status_code=response.status_code,
                raw_response=raw_text,
                structured_data=parsed,
                tools_called=tools_called,
                payload_sent=test_case.payload,
            )
        except Exception as exc:
            logger.warning("MCP communication error: %s", exc)
            return ExecutionResult(
                test_case_id=test_case.id,
                protocol="mcp",
                status_code=503,
                raw_response=f"MCP Connection Error: {str(exc)}",
                error_message=str(exc),
                payload_sent=test_case.payload,
            )
