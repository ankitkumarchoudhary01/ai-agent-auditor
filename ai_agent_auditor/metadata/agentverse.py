"""
Agentverse / Almanac Metadata Retrieval Client.
"""

from typing import Any, Dict, List, Optional
import httpx
from ai_agent_auditor.models.metadata import (
    AgentCapability,
    AgentEndpoint,
    AgentMetadata,
    RiskLevel,
)
from ai_agent_auditor.config import AuditorConfig


class AgentverseClient:
    """Client for retrieving agent metadata and capability manifests from Agentverse."""

    def __init__(self, config: AuditorConfig, http_client: Optional[httpx.Client] = None):
        self.config = config
        self.http_client = http_client or httpx.Client(timeout=config.request_timeout_seconds)

    def fetch_agent_metadata(self, address: str) -> AgentMetadata:
        """Fetch metadata for an agent by address, falling back to mock or local registry if needed."""
        # 1. First check if address is a known mock / local agent
        from ai_agent_auditor.metadata.registry import get_mock_agent_metadata

        mock_data = get_mock_agent_metadata(address)
        if mock_data:
            return self._enrich_metadata_warnings(mock_data)

        # 2. Query Agentverse Almanac API
        headers = {
            "Accept": "application/json",
            "User-Agent": "AI-Agent-Auditor/1.0",
        }
        if self.config.agentverse_api_key:
            headers["Authorization"] = f"Bearer {self.config.agentverse_api_key}"

        url = f"{self.config.agentverse_base_url.rstrip('/')}/almanac/agents/{address}"
        try:
            response = self.http_client.get(url, headers=headers)
            if response.status_code == 200:
                raw_json = response.json()
                metadata = self._parse_agentverse_response(address, raw_json)
                return self._enrich_metadata_warnings(metadata)
        except Exception:
            # When remote request fails (offline, rate limited, or mock address), fall back
            pass

        # 3. Fallback: Generate structured metadata for unknown address
        return self._create_generic_metadata(address)

    def _parse_agentverse_response(self, address: str, data: Dict[str, Any]) -> AgentMetadata:
        """Parse raw Agentverse API response into AgentMetadata model."""
        name = data.get("name") or data.get("title") or f"Agent-{address[:10]}"
        description = data.get("description", "")
        protocols = data.get("protocols", [])

        endpoints: List[AgentEndpoint] = []
        for ep in data.get("endpoints", []):
            if isinstance(ep, dict):
                endpoints.append(
                    AgentEndpoint(
                        protocol=ep.get("protocol", "uagents"),
                        url=ep.get("url", ""),
                        metadata=ep.get("metadata", {}),
                    )
                )
            elif isinstance(ep, str):
                endpoints.append(
                    AgentEndpoint(protocol="uagents", url=ep, metadata={})
                )

        capabilities: List[AgentCapability] = []
        for cap in data.get("capabilities", []):
            if isinstance(cap, dict):
                risk = RiskLevel.MEDIUM
                name_lower = cap.get("name", "").lower()
                if any(k in name_lower for k in ["admin", "exec", "eval", "transfer", "delete", "write"]):
                    risk = RiskLevel.HIGH
                capabilities.append(
                    AgentCapability(
                        name=cap.get("name", "unknown_capability"),
                        description=cap.get("description", ""),
                        parameters_schema=cap.get("parameters", {}),
                        risk_level=risk,
                        requires_auth=cap.get("requires_auth", True),
                    )
                )

        return AgentMetadata(
            address=address,
            name=name,
            description=description,
            protocols=protocols or ["uagents"],
            endpoints=endpoints,
            capabilities=capabilities,
            registry_source="agentverse",
            raw_manifest=data,
        )

    def _create_generic_metadata(self, address: str) -> AgentMetadata:
        """Generate a basic AgentMetadata object when remote lookup is unavailable."""
        return AgentMetadata(
            address=address,
            name=f"Agent-{address[-8:] if len(address) > 8 else address}",
            description="Agent discovered via address lookup.",
            protocols=["uagents", "mock"],
            endpoints=[
                AgentEndpoint(protocol="mock", url=f"mock://{address}", metadata={})
            ],
            capabilities=[
                AgentCapability(
                    name="chat_message",
                    description="General conversational messaging handler.",
                    risk_level=RiskLevel.LOW,
                    requires_auth=False,
                )
            ],
            registry_source="local",
            raw_manifest={"address": address, "source": "fallback"},
            metadata_warnings=[
                "Agent was not found in remote Agentverse registry; using local fallback profile."
            ],
        )

    def _enrich_metadata_warnings(self, metadata: AgentMetadata) -> AgentMetadata:
        """Perform static security analysis on agent metadata to surface potential risks."""
        warnings: List[str] = list(metadata.metadata_warnings)

        # Check capabilities
        for cap in metadata.capabilities:
            cap_lower = cap.name.lower()
            if any(term in cap_lower for term in ["exec", "shell", "eval", "cmd"]):
                warnings.append(
                    f"Static Observation: Capability '{cap.name}' advertises system execution semantics."
                )
            if any(term in cap_lower for term in ["transfer", "payment", "withdraw"]) and not cap.requires_auth:
                warnings.append(
                    f"Static Observation: Financial capability '{cap.name}' does not explicitly enforce authentication."
                )
            if any(term in cap_lower for term in ["sql", "query", "database"]):
                warnings.append(
                    f"Static Observation: Database capability '{cap.name}' may be subject to structured injection."
                )

        # Check endpoints
        for ep in metadata.endpoints:
            if ep.url.startswith("http://"):
                warnings.append(
                    f"Static Observation: Endpoint '{ep.url}' utilizes unencrypted HTTP protocol."
                )

        metadata.metadata_warnings = list(dict.fromkeys(warnings))
        return metadata
