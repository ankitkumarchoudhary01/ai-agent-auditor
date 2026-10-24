"""
Fetch.ai uAgents Protocol Adapter.
"""

import base64
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


class UAgentsAdapter(BaseProtocolAdapter):
    """Adapter for communicating with Fetch.ai uAgents via HTTP webhook or mailbox."""

    def __init__(self, config: AuditorConfig, http_client: Optional[httpx.Client] = None):
        super().__init__(config)
        self.http_client = http_client or httpx.Client(timeout=config.request_timeout_seconds)

    def _send_payload(
        self,
        test_case: SecurityTestCase,
        endpoint: Optional[AgentEndpoint],
    ) -> ExecutionResult:
        if not endpoint or not endpoint.url:
            raise ValueError("Endpoint URL required for uAgents communication.")

        url = endpoint.url
        # Construct standard uAgent JSON-RPC / envelope message
        payload_data = {
            "message": test_case.payload,
            "tool_call": test_case.tool_call_target,
            "tool_arguments": test_case.tool_call_arguments,
        }

        # uAgents payload is often JSON or base64 encoded JSON
        envelope = {
            "version": "1.0",
            "sender": "agent1q_auditor_security_scanner",
            "target": endpoint.metadata.get("target_address", "target_agent"),
            "protocol": "uagent_security_audit_v1",
            "payload": base64.b64encode(json.dumps(payload_data).encode()).decode(),
        }

        try:
            response = self.http_client.post(
                url,
                json=envelope,
                headers={"Content-Type": "application/json", "User-Agent": "AI-Agent-Auditor/1.0"},
            )
            raw_text = response.text
            parsed_json = None
            try:
                parsed_json = response.json()
            except Exception:
                pass

            return ExecutionResult(
                test_case_id=test_case.id,
                protocol="uagents",
                status_code=response.status_code,
                raw_response=raw_text,
                structured_data=parsed_json,
                payload_sent=test_case.payload,
            )
        except Exception as exc:
            logger.warning("uAgents endpoint communication failed: %s", exc)
            return ExecutionResult(
                test_case_id=test_case.id,
                protocol="uagents",
                status_code=503,
                raw_response=f"Connection Error: {str(exc)}",
                error_message=str(exc),
                payload_sent=test_case.payload,
            )
