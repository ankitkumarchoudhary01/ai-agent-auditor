"""
Agent-to-Agent (A2A) REST Protocol Adapter.
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


class A2AAdapter(BaseProtocolAdapter):
    """Adapter for generic Agent-to-Agent (A2A) REST communication."""

    def __init__(self, config: AuditorConfig, http_client: Optional[httpx.Client] = None):
        super().__init__(config)
        self.http_client = http_client or httpx.Client(timeout=config.request_timeout_seconds)

    def _send_payload(
        self,
        test_case: SecurityTestCase,
        endpoint: Optional[AgentEndpoint],
    ) -> ExecutionResult:
        if not endpoint or not endpoint.url:
            raise ValueError("Endpoint URL required for A2A communication.")

        url = endpoint.url
        body: Dict[str, Any] = {
            "prompt": test_case.payload,
            "category": test_case.category.value,
        }
        if test_case.tool_call_target:
            body["tool_request"] = {
                "name": test_case.tool_call_target,
                "arguments": test_case.tool_call_arguments or {},
            }

        tools_called = []
        try:
            response = self.http_client.post(
                url,
                json=body,
                headers={"Content-Type": "application/json", "User-Agent": "AI-Agent-Auditor/1.0"},
            )
            raw_text = response.text
            parsed = None
            try:
                parsed = response.json()
                if isinstance(parsed, dict) and "executed_tool" in parsed:
                    tools_called.append(parsed["executed_tool"])
            except Exception:
                pass

            return ExecutionResult(
                test_case_id=test_case.id,
                protocol="a2a",
                status_code=response.status_code,
                raw_response=raw_text,
                structured_data=parsed,
                tools_called=tools_called,
                payload_sent=test_case.payload,
            )
        except Exception as exc:
            logger.warning("A2A communication error: %s", exc)
            return ExecutionResult(
                test_case_id=test_case.id,
                protocol="a2a",
                status_code=503,
                raw_response=f"A2A Connection Error: {str(exc)}",
                error_message=str(exc),
                payload_sent=test_case.payload,
            )
