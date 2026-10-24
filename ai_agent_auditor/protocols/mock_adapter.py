"""
Protocol adapter for in-memory and simulated mock agents.
"""

from typing import Dict, Optional
from ai_agent_auditor.config import AuditorConfig
from ai_agent_auditor.mock_agent.agent import MockAgent
from ai_agent_auditor.models.metadata import AgentEndpoint
from ai_agent_auditor.models.result import ExecutionResult
from ai_agent_auditor.models.test_case import SecurityTestCase
from ai_agent_auditor.protocols.base import BaseProtocolAdapter


class MockProtocolAdapter(BaseProtocolAdapter):
    """Adapter for interacting with in-memory MockAgent instances."""

    def __init__(self, config: AuditorConfig):
        super().__init__(config)
        self._mock_agents: Dict[str, MockAgent] = {}

    def register_agent_instance(self, address: str, agent: MockAgent) -> None:
        """Register a specific mock agent instance."""
        self._mock_agents[address] = agent

    def get_or_create_agent(self, address: str) -> MockAgent:
        """Get or instantiate a default mock agent for the address."""
        if address in self._mock_agents:
            return self._mock_agents[address]

        # Determine mode based on address name
        mode = "hardened" if "hardened" in address.lower() else "vulnerable"
        agent = MockAgent(address=address, mode=mode)
        self._mock_agents[address] = agent
        return agent

    def _send_payload(
        self,
        test_case: SecurityTestCase,
        endpoint: Optional[AgentEndpoint],
    ) -> ExecutionResult:
        address = "default_mock"
        if endpoint and endpoint.url.startswith("mock://"):
            address = endpoint.url[len("mock://"):]

        agent = self.get_or_create_agent(address)
        return agent.handle_message(
            payload=test_case.payload,
            protocol=test_case.protocol,
            tool_call_target=test_case.tool_call_target,
            tool_call_arguments=test_case.tool_call_arguments,
        )
