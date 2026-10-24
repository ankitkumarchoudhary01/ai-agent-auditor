"""
Base protocol adapter interface and execution safeguards.
"""

from abc import ABC, abstractmethod
import time
from typing import Optional
from ai_agent_auditor.models.metadata import AgentEndpoint
from ai_agent_auditor.models.test_case import ApprovalStatus, SecurityTestCase
from ai_agent_auditor.models.result import ExecutionResult
from ai_agent_auditor.config import AuditorConfig


class BaseProtocolAdapter(ABC):
    """Abstract base class for all agent communication protocol adapters."""

    def __init__(self, config: AuditorConfig):
        self.config = config

    def execute(
        self,
        test_case: SecurityTestCase,
        endpoint: Optional[AgentEndpoint] = None,
    ) -> ExecutionResult:
        """Execute a security test with mandatory authorization and timing controls."""
        # Enforce authorization guardrail
        if test_case.approval_status != ApprovalStatus.APPROVED:
            raise PermissionError(
                f"Unauthorized test execution: Test '{test_case.id}' has status '{test_case.approval_status.value}'. "
                "Tests must be explicitly approved before execution."
            )

        start_time = time.perf_counter()
        try:
            result = self._send_payload(test_case, endpoint)
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                test_case_id=test_case.id,
                protocol=test_case.protocol,
                status_code=500,
                raw_response=f"Execution error: {str(exc)}",
                response_time_ms=duration_ms,
                error_message=str(exc),
                payload_sent=test_case.payload,
            )

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        result.response_time_ms = duration_ms
        result.test_case_id = test_case.id
        return result

    @abstractmethod
    def _send_payload(
        self,
        test_case: SecurityTestCase,
        endpoint: Optional[AgentEndpoint],
    ) -> ExecutionResult:
        """Protocol-specific implementation to transmit payload and parse response."""
        pass
