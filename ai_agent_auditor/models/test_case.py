"""
Data models for security test cases and authorization approval.
"""

from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class TestCategory(str, Enum):
    __test__ = False

    PROMPT_INJECTION = "prompt_injection"
    UNAUTHORIZED_TOOL_USAGE = "unauthorized_tool_usage"
    DATA_LEAKAGE = "data_leakage"
    INPUT_VALIDATION = "input_validation"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class SecurityTestCase(BaseModel):
    """Specification of an automated security probe to test against an agent."""

    id: str = Field(..., description="Unique test case identifier (e.g. SEC-PI-01).")
    category: TestCategory = Field(
        ..., description="Security vulnerability category being tested."
    )
    name: str = Field(..., description="Short descriptive test name.")
    description: str = Field(..., description="Detailed explanation of the test objective.")
    payload: str = Field(
        ..., description="The user prompt or message payload delivered to the agent."
    )
    protocol: str = Field(
        default="mock", description="Protocol to test over (uagents, mcp, a2a, mock)."
    )
    tool_call_target: Optional[str] = Field(
        default=None,
        description="Name of tool being tested for unauthorized invocation, if applicable.",
    )
    tool_call_arguments: Optional[Dict[str, Any]] = Field(
        default=None, description="Arguments for tool call testing."
    )
    canary_token: Optional[str] = Field(
        default=None,
        description="A unique synthetic canary string to detect in responses (for leakage/injection).",
    )
    expected_secure_behavior: str = Field(
        ...,
        description="How a secure, compliant agent is expected to respond (e.g. refuse or sanitize).",
    )
    violation_criteria: str = Field(
        ...,
        description="Conditions indicating a vulnerability (e.g. canary reflected, tool executed).",
    )
    severity_potential: str = Field(
        default="medium",
        description="Potential severity if vulnerable: 'low', 'medium', 'high', 'critical'.",
    )
    approval_status: ApprovalStatus = Field(
        default=ApprovalStatus.PENDING,
        description="Authorization approval status for executing this test.",
    )
    rejection_reason: Optional[str] = Field(
        default=None, description="Reason if test case was rejected."
    )
    is_simulated: bool = Field(
        default=False,
        description="Flag indicating if the test is running against a mock/simulated environment.",
    )
