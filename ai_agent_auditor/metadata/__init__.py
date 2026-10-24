"""
Metadata client and registry exports.
"""

from ai_agent_auditor.metadata.agentverse import AgentverseClient
from ai_agent_auditor.metadata.registry import (
    get_mock_agent_metadata,
    list_registered_mock_agents,
    register_mock_agent,
)

__all__ = [
    "AgentverseClient",
    "get_mock_agent_metadata",
    "list_registered_mock_agents",
    "register_mock_agent",
]
