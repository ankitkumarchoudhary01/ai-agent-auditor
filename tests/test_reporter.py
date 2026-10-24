"""
Unit tests for the report generator and exporter.
"""

from unittest.mock import MagicMock
from ai_agent_auditor.models.report import (
    AuditReport,
    FindingType,
    SecurityFinding,
    Severity,
)
from ai_agent_auditor.models.test_case import TestCategory
from ai_agent_auditor.reporter.exporter import ReportExporter
from ai_agent_auditor.reporter.templates import generate_markdown_report


def test_markdown_report_formatting():
    finding = SecurityFinding(
        id="FIND-01",
        title="Unauthorized Transfer Funds Execution",
        category=TestCategory.UNAUTHORIZED_TOOL_USAGE,
        severity=Severity.HIGH,
        finding_type=FindingType.CONFIRMED_VULNERABILITY,
        confidence=0.98,
        description="Agent executed transfer_funds without validating bearer authentication.",
        reproduction_steps=["1. Send tool payload", "2. Verify execution"],
        evidence=["Tool record executed: {'tool': 'transfer_funds'}"],
        remediation="Require authentication before calling transfer_funds.",
        affected_tool_or_protocol="transfer_funds",
    )

    report = AuditReport(
        audit_id="aud_unit_test_99",
        target_address="agent1qtest_target",
        target_name="Test Bank Agent",
        target_protocols=["uagents", "mock"],
        total_tests_generated=5,
        total_tests_executed=5,
        confirmed_vulnerabilities_count=1,
        simulated_vulnerabilities_count=0,
        metadata_warnings_count=1,
        findings=[finding],
        metadata_warnings=["Static Observation: transfer_funds requires critical review."],
        is_simulated_run=False,
        summary="Audit identified 1 confirmed vulnerability on live system.",
    )

    md = generate_markdown_report(report)
    assert "# AI Agent Security Audit Report" in md
    assert "aud_unit_test_99" in md
    assert "Test Bank Agent" in md
    assert "Confirmed Vulnerabilities" in md
    assert "Unauthorized Transfer Funds Execution" in md
    assert "Empirical Evidence Captured" in md
    assert "Require authentication before calling transfer_funds." in md


def test_report_exporter_writes_files(test_config, tmp_path):
    test_config.output_dir = str(tmp_path / "reports_test")
    exporter = ReportExporter(test_config)

    report = AuditReport(
        audit_id="aud_export_001",
        target_address="agent1qexport_target",
        target_name="Export Target Agent",
        total_tests_generated=2,
        total_tests_executed=2,
        confirmed_vulnerabilities_count=0,
        simulated_vulnerabilities_count=0,
        metadata_warnings_count=0,
        summary="Clean audit run.",
    )

    json_path, md_path, submitted = exporter.export(report)
    assert json_path.exists()
    assert md_path.exists()
    assert submitted is None

    # Check content of JSON
    json_text = json_path.read_text(encoding="utf-8")
    assert "aud_export_001" in json_text

    # Check content of Markdown
    md_text = md_path.read_text(encoding="utf-8")
    assert "Clean audit run" in md_text


def test_report_exporter_webhook_submission(test_config, tmp_path):
    mock_http = MagicMock()
    mock_http.post.return_value.status_code = 200

    test_config.output_dir = str(tmp_path / "reports_webhook")
    test_config.destination_webhook_url = "https://security-dashboard.internal/api/audit"

    exporter = ReportExporter(test_config, http_client=mock_http)
    report = AuditReport(
        audit_id="aud_webhook_002",
        target_address="agent1qwebhook",
        target_name="Webhook Agent",
        summary="Webhook test",
    )

    _, _, submitted = exporter.export(report)
    assert submitted is True
    assert mock_http.post.called
    assert mock_http.post.call_args.args[0] == "https://security-dashboard.internal/api/audit"
