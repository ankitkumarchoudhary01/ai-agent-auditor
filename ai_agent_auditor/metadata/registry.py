"""
Local mock and registered agent catalog for reproducible testing and offline audits.
"""

from typing import Dict, Optional
from ai_agent_auditor.models.metadata import (
    AgentCapability,
    AgentEndpoint,
    AgentMetadata,
    RiskLevel,
)

# Registry of pre-configured agents for testing and local simulation
_MOCK_REGISTRY: Dict[str, AgentMetadata] = {
    "agent1qvulnerable_demo_001": AgentMetadata(
        address="agent1qvulnerable_demo_001",
        name="Vulnerable Finance & Operations Agent",
        description="Demo autonomous assistant with wallet transfer, balance lookup, and file reading tools.",
        version="0.9.0",
        protocols=["mock", "uagents", "mcp"],
        endpoints=[
            AgentEndpoint(protocol="mock", url="mock://agent1qvulnerable_demo_001"),
            AgentEndpoint(protocol="uagents", url="http://127.0.0.1:8000/submit"),
            AgentEndpoint(protocol="mcp", url="http://127.0.0.1:8001/mcp"),
        ],
        capabilities=[
            AgentCapability(
                name="transfer_funds",
                description="Transfer crypto or tokens to a recipient address.",
                parameters_schema={
                    "type": "object",
                    "properties": {
                        "recipient": {"type": "string"},
                        "amount": {"type": "number"},
                    },
                    "required": ["recipient", "amount"],
                },
                risk_level=RiskLevel.CRITICAL,
                requires_auth=True,
            ),
            AgentCapability(
                name="read_internal_document",
                description="Fetch internal documentation by file key.",
                parameters_schema={
                    "type": "object",
                    "properties": {"doc_id": {"type": "string"}},
                    "required": ["doc_id"],
                },
                risk_level=RiskLevel.HIGH,
                requires_auth=True,
            ),
            AgentCapability(
                name="check_balance",
                description="Check current balance for an account.",
                parameters_schema={"type": "object", "properties": {"account": {"type": "string"}}},
                risk_level=RiskLevel.LOW,
                requires_auth=False,
            ),
        ],
        registry_source="mock",
        raw_manifest={"vulnerable": True, "mode": "unfiltered"},
        metadata_warnings=[
            "Static Observation: Capability 'transfer_funds' involves critical financial operations."
        ],
    ),
    "agent1qhardened_demo_002": AgentMetadata(
        address="agent1qhardened_demo_002",
        name="Hardened Secure Support Agent",
        description="Enterprise customer support agent with strict boundary validation and authorization checks.",
        version="2.0.1",
        protocols=["mock", "uagents", "a2a"],
        endpoints=[
            AgentEndpoint(protocol="mock", url="mock://agent1qhardened_demo_002"),
            AgentEndpoint(protocol="uagents", url="http://127.0.0.1:8002/submit"),
            AgentEndpoint(protocol="a2a", url="http://127.0.0.1:8002/api/v1/agent"),
        ],
        capabilities=[
            AgentCapability(
                name="lookup_faq",
                description="Lookup public knowledgebase documentation.",
                parameters_schema={"type": "object", "properties": {"query": {"type": "string"}}},
                risk_level=RiskLevel.LOW,
                requires_auth=False,
            ),
            AgentCapability(
                name="submit_ticket",
                description="Create a sanitized support ticket.",
                parameters_schema={"type": "object", "properties": {"subject": {"type": "string"}, "body": {"type": "string"}}},
                risk_level=RiskLevel.LOW,
                requires_auth=False,
            ),
        ],
        registry_source="mock",
        raw_manifest={"hardened": True, "mode": "guarded"},
        metadata_warnings=[],
    ),
    "agent1qmcp_demo_003": AgentMetadata(
        address="agent1qmcp_demo_003",
        name="MCP File and Search Agent",
        description="Agent providing tools via Model Context Protocol.",
        version="1.0.0",
        protocols=["mcp", "mock"],
        endpoints=[
            AgentEndpoint(protocol="mcp", url="http://127.0.0.1:8003/mcp"),
            AgentEndpoint(protocol="mock", url="mock://agent1qmcp_demo_003"),
        ],
        capabilities=[
            AgentCapability(
                name="search_database",
                description="Search internal relational database records.",
                parameters_schema={"type": "object", "properties": {"query": {"type": "string"}}},
                risk_level=RiskLevel.HIGH,
                requires_auth=True,
            ),
            AgentCapability(
                name="read_file",
                description="Read server filesystem contents.",
                parameters_schema={"type": "object", "properties": {"path": {"type": "string"}}},
                risk_level=RiskLevel.CRITICAL,
                requires_auth=True,
            ),
        ],
        registry_source="mock",
        raw_manifest={"mcp_enabled": True},
        metadata_warnings=[
            "Static Observation: Capability 'read_file' advertises direct filesystem access."
        ],
    ),
}


def register_mock_agent(metadata: AgentMetadata) -> None:
    """Register a custom mock agent for test scenarios."""
    _MOCK_REGISTRY[metadata.address] = metadata


def get_mock_agent_metadata(address: str) -> Optional[AgentMetadata]:
    """Retrieve metadata for a mock agent address if registered."""
    return _MOCK_REGISTRY.get(address)


def list_registered_mock_agents() -> Dict[str, AgentMetadata]:
    """List all pre-configured mock agents."""
    return dict(_MOCK_REGISTRY)
