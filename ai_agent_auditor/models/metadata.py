"""
Pydantic data models for agent metadata and capabilities.
"""

from typing import Any, Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentCapability(BaseModel):
    """Represents a declared tool, function, or skill of the target agent."""

    name: str = Field(..., description="Name of the function or capability.")
    description: str = Field("", description="Functional description.")
    parameters_schema: Dict[str, Any] = Field(
        default_factory=dict, description="JSON Schema for parameters."
    )
    risk_level: RiskLevel = Field(
        default=RiskLevel.MEDIUM, description="Assessed risk level of this capability."
    )
    requires_auth: bool = Field(
        default=True, description="Whether invocation requires authenticated permission."
    )


class AgentEndpoint(BaseModel):
    """Represents a reachable endpoint or protocol address for the agent."""

    protocol: str = Field(..., description="Protocol: 'uagents', 'mcp', 'a2a', or 'mock'.")
    url: str = Field(..., description="Endpoint URL or network address.")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Protocol-specific metadata."
    )


class AgentMetadata(BaseModel):
    """Aggregated metadata for an agent retrieved from Agentverse or registry."""

    address: str = Field(..., description="Unique agent address or identifier.")
    name: str = Field(default="Unknown Agent", description="Display name of the agent.")
    description: str = Field(default="", description="High-level description of agent purpose.")
    version: Optional[str] = Field(default="1.0.0", description="Agent version.")
    protocols: List[str] = Field(
        default_factory=list, description="Supported communication protocols."
    )
    endpoints: List[AgentEndpoint] = Field(
        default_factory=list, description="List of accessible endpoints."
    )
    capabilities: List[AgentCapability] = Field(
        default_factory=list, description="Declared capabilities/tools."
    )
    system_prompt_hint: Optional[str] = Field(
        default=None, description="Hints or guidelines about the agent's system prompt if known."
    )
    registry_source: str = Field(
        default="agentverse", description="Source registry ('agentverse', 'local', 'mock')."
    )
    raw_manifest: Dict[str, Any] = Field(
        default_factory=dict, description="Raw unparsed manifest dictionary."
    )
    metadata_warnings: List[str] = Field(
        default_factory=list,
        description="Non-confirmed static metadata observations (e.g. wide permission scope).",
    )
