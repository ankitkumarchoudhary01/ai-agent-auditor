"""
Data models for the security audit findings and executive report.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from ai_agent_auditor.models.test_case import TestCategory


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    CONFIRMED_VULNERABILITY = "confirmed_vulnerability"
    SIMULATED_VULNERABILITY = "simulated_vulnerability"
    METADATA_WARNING = "metadata_warning"
    INFORMATIONAL = "informational"


class SecurityFinding(BaseModel):
    """An individual security finding backed by empirical evidence or manifest analysis."""

    id: str = Field(..., description="Unique finding ID (e.g. FIND-01).")
    title: str = Field(..., description="Concise title of the finding.")
    category: TestCategory = Field(..., description="Security category.")
    severity: Severity = Field(..., description="Assessed severity level.")
    finding_type: FindingType = Field(
        ...,
        description="Type: 'confirmed_vulnerability', 'simulated_vulnerability', 'metadata_warning', or 'informational'.",
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0."
    )
    description: str = Field(..., description="Detailed description of the vulnerability.")
    reproduction_steps: List[str] = Field(
        default_factory=list,
        description="Exact step-by-step instructions to reproduce the issue.",
    )
    evidence: List[str] = Field(
        default_factory=list,
        description="Concrete empirical evidence (e.g. leaked string, tool call name, raw snippet).",
    )
    remediation: str = Field(
        ..., description="Specific, actionable guidance to resolve the security weakness."
    )
    affected_tool_or_protocol: Optional[str] = Field(
        default=None, description="Specific tool or protocol affected."
    )

    @property
    def is_confirmed(self) -> bool:
        """Returns True ONLY if this is a confirmed vulnerability from live dynamic testing."""
        return self.finding_type == FindingType.CONFIRMED_VULNERABILITY


class AuditReport(BaseModel):
    """Complete security audit report for an AI Agent."""

    audit_id: str = Field(..., description="Unique report ID.")
    target_address: str = Field(..., description="Audited agent address.")
    target_name: str = Field(default="Unknown Agent", description="Audited agent name.")
    target_protocols: List[str] = Field(
        default_factory=list, description="Protocols supported by target."
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the audit.",
    )
    total_tests_generated: int = Field(default=0)
    total_tests_executed: int = Field(default=0)
    confirmed_vulnerabilities_count: int = Field(default=0)
    simulated_vulnerabilities_count: int = Field(default=0)
    metadata_warnings_count: int = Field(default=0)
    findings: List[SecurityFinding] = Field(default_factory=list)
    metadata_warnings: List[str] = Field(default_factory=list)
    is_simulated_run: bool = Field(
        default=False,
        description="Flag indicating whether this audit ran against a local/mock simulation.",
    )
    summary: str = Field(..., description="Executive summary of the security audit results.")
    raw_metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Metadata captured during audit."
    )
