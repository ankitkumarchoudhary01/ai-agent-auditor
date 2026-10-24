"""
Protocol adapter factory and resolution registry.
"""

from typing import Dict, Type
from ai_agent_auditor.config import AuditorConfig
from ai_agent_auditor.protocols.base import BaseProtocolAdapter
from ai_agent_auditor.protocols.mock_adapter import MockProtocolAdapter
from ai_agent_auditor.protocols.uagents_adapter import UAgentsAdapter
from ai_agent_auditor.protocols.mcp_adapter import MCPAdapter
from ai_agent_auditor.protocols.a2a_adapter import A2AAdapter

_ADAPTER_REGISTRY: Dict[str, Type[BaseProtocolAdapter]] = {
    "mock": MockProtocolAdapter,
    "uagents": UAgentsAdapter,
    "mcp": MCPAdapter,
    "a2a": A2AAdapter,
}


def get_protocol_adapter(protocol: str, config: AuditorConfig) -> BaseProtocolAdapter:
    """Resolve and return an instantiated adapter for the specified protocol."""
    proto_clean = protocol.lower().strip()
    adapter_cls = _ADAPTER_REGISTRY.get(proto_clean, MockProtocolAdapter)
    return adapter_cls(config)


def register_protocol_adapter(protocol: str, adapter_cls: Type[BaseProtocolAdapter]) -> None:
    """Register a custom protocol adapter class."""
    _ADAPTER_REGISTRY[protocol.lower().strip()] = adapter_cls
