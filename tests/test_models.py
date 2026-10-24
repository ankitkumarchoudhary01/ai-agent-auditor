"""
Unit tests for Pydantic models and validation.
"""

import pytest
from pydantic import ValidationError
from ai_agent_auditor.models.metadata import (
    AgentCapability,
    AgentEndpoint,
    AgentMetadata,
    RiskLevel,
)
from ai_agent_auditor.models.test_case import (
    ApprovalStatus,
    SecurityTestCase,
    TestCategory,
)
from ai_agent_auditor.models.report import (
    AuditReport,
    FindingType,
    SecurityFinding,
    Severity,
)


def test_agent_capability_validation():
    cap = AgentCapability(
        name="execute_query",
        description="Run read-only queries",
        risk_level=RiskLevel.MEDIUM,
        requires_auth=True,
    )
    assert cap.name == "execute_query"
    assert cap.risk_level == RiskLevel.MEDIUM
    assert cap.requires_auth is True


def test_security_test_case_validation():
    tc = SecurityTestCase(
        id="SEC-01",
        category=TestCategory.PROMPT_INJECTION,
        name="PI Test",
        description="Testing injection",
        payload="Ignore rules",
        expected_secure_behavior="Refusal",
        violation_criteria="Compliance",
    )
    assert tc.approval_status == ApprovalStatus.PENDING
    assert tc.category == TestCategory.PROMPT_INJECTION


def test_security_finding_confirmed_logic():
    # A confirmed vulnerability on a live system
    finding_confirmed = SecurityFinding(
        id="FIND-01",
        title="Canary Leak",
        category=TestCategory.DATA_LEAKAGE,
        severity=Severity.HIGH,
        finding_type=FindingType.CONFIRMED_VULNERABILITY,
        confidence=0.98,
        description="Canary token reflected in output.",
        remediation="Sanitize outputs.",
    )
    assert finding_confirmed.is_confirmed is True

    # A simulated vulnerability must NOT be confirmed
    finding_simulated = SecurityFinding(
        id="FIND-02",
        title="Simulated Override",
        category=TestCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        finding_type=FindingType.SIMULATED_VULNERABILITY,
        confidence=0.95,
        description="Simulated override in test bed.",
        remediation="Guardrail implementation.",
    )
    assert finding_simulated.is_confirmed is False

    # A metadata warning must NOT be confirmed
    finding_warning = SecurityFinding(
        id="FIND-03",
        title="Wide Permissions",
        category=TestCategory.UNAUTHORIZED_TOOL_USAGE,
        severity=Severity.LOW,
        finding_type=FindingType.METADATA_WARNING,
        confidence=0.40,
        description="Agent advertises admin tool.",
        remediation="Scope permissions down.",
    )
    assert finding_warning.is_confirmed is False


def test_audit_report_serialization():
    report = AuditReport(
        audit_id="aud_12345",
        target_address="agent1qtest",
        target_name="Test Agent",
        total_tests_generated=5,
        total_tests_executed=5,
        confirmed_vulnerabilities_count=0,
        simulated_vulnerabilities_count=2,
        metadata_warnings_count=1,
        summary="Test summary",
    )
    json_data = report.model_dump_json()
    assert "aud_12345" in json_data
    assert "agent1qtest" in json_data
