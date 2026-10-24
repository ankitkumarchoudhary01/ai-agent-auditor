"""
End-to-End Integration Tests for the complete AI Agent Auditor workflow.
"""

from ai_agent_auditor.auditor import AgentAuditor
from ai_agent_auditor.config import AuditorConfig
from ai_agent_auditor.models.report import FindingType
from ai_agent_auditor.models.test_case import TestCategory


def test_e2e_audit_vulnerable_mock_agent(tmp_path):
    config = AuditorConfig(
        output_dir=str(tmp_path / "e2e_reports"),
        require_human_approval=False,
        rate_limit_delay_seconds=0.0,
    )
    auditor = AgentAuditor(config=config)

    report = auditor.audit_agent(
        address="agent1qvulnerable_demo_001",
        auto_approve=True,
        export_reports=True,
    )

    # 1. Verification of metadata retrieval
    assert report.target_name == "Vulnerable Finance & Operations Agent"
    assert "uagents" in report.target_protocols
    assert "mcp" in report.target_protocols

    # 2. Verification of test execution
    assert report.total_tests_generated >= 4
    assert report.total_tests_executed == report.total_tests_generated

    # 3. Verification of vulnerability detection
    # In vulnerable mode, mock agent violates prompt injection, unauthorized tool usage, and secret leakage
    assert report.simulated_vulnerabilities_count >= 3
    # Critical rule: on simulated runs, confirmed count MUST be 0!
    assert report.confirmed_vulnerabilities_count == 0
    assert report.is_simulated_run is True

    # 4. Check findings detail
    finding_categories = {f.category for f in report.findings}
    assert TestCategory.PROMPT_INJECTION in finding_categories
    assert TestCategory.UNAUTHORIZED_TOOL_USAGE in finding_categories
    assert TestCategory.DATA_LEAKAGE in finding_categories

    for f in report.findings:
        if f.finding_type == FindingType.SIMULATED_VULNERABILITY:
            assert f.is_confirmed is False
            assert len(f.evidence) > 0
            assert len(f.reproduction_steps) > 0
            assert f.remediation is not None

    # 5. Verify reports were exported to disk
    json_file = tmp_path / "e2e_reports" / f"audit_{report.audit_id}.json"
    md_file = tmp_path / "e2e_reports" / f"audit_{report.audit_id}.md"
    assert json_file.exists()
    assert md_file.exists()


def test_e2e_audit_hardened_mock_agent(tmp_path):
    config = AuditorConfig(
        output_dir=str(tmp_path / "e2e_hardened_reports"),
        require_human_approval=False,
        rate_limit_delay_seconds=0.0,
    )
    auditor = AgentAuditor(config=config)

    report = auditor.audit_agent(
        address="agent1qhardened_demo_002",
        auto_approve=True,
        export_reports=True,
    )

    assert report.target_name == "Hardened Secure Support Agent"
    assert report.total_tests_executed >= 4

    # Hardened agent must NOT yield any simulated or confirmed vulnerabilities
    assert report.simulated_vulnerabilities_count == 0
    assert report.confirmed_vulnerabilities_count == 0
    assert "SECURE POSTURE" in report.summary
