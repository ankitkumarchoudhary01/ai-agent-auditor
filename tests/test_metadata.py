"""
Unit tests for Agentverse metadata retrieval and static warnings.
"""

from unittest.mock import MagicMock
import httpx
from ai_agent_auditor.config import AuditorConfig
from ai_agent_auditor.metadata.agentverse import AgentverseClient
from ai_agent_auditor.metadata.registry import get_mock_agent_metadata


def test_fetch_known_mock_agent(test_config):
    client = AgentverseClient(test_config)
    metadata = client.fetch_agent_metadata("agent1qvulnerable_demo_001")
    assert metadata is not None
    assert metadata.address == "agent1qvulnerable_demo_001"
    assert metadata.name == "Vulnerable Finance & Operations Agent"
    assert len(metadata.capabilities) >= 3
    # Check that transfer_funds capability exists
    tool_names = [c.name for c in metadata.capabilities]
    assert "transfer_funds" in tool_names
    # Check static observation warnings
    assert len(metadata.metadata_warnings) > 0


def test_fetch_unknown_agent_fallback(test_config):
    # Mock http client that returns 404
    mock_http = MagicMock()
    mock_http.get.return_value.status_code = 404

    client = AgentverseClient(test_config, http_client=mock_http)
    metadata = client.fetch_agent_metadata("agent1qunknown_address_999")
    assert metadata.address == "agent1qunknown_address_999"
    assert metadata.registry_source == "local"
    assert any("fallback profile" in w for w in metadata.metadata_warnings)


def test_metadata_warnings_enrichment(test_config):
    client = AgentverseClient(test_config)
    raw_data = {
        "name": "Shell Exec Agent",
        "endpoints": ["http://insecure-domain.com/submit"],
        "capabilities": [
            {"name": "exec_shell_command", "requires_auth": False},
            {"name": "transfer_tokens", "requires_auth": False},
        ],
    }
    meta = client._parse_agentverse_response("agent1qdangerous", raw_data)
    enriched = client._enrich_metadata_warnings(meta)

    # Check that static warnings were identified for system execution and unauthenticated transfer
    warning_text = " ".join(enriched.metadata_warnings)
    assert "system execution semantics" in warning_text
    assert "unencrypted HTTP" in warning_text
