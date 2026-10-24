"""
Data models for test execution and evaluation results.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from ai_agent_auditor.models.test_case import TestCategory


class ExecutionResult(BaseModel):
    """Raw response details captured during test execution."""

    test_case_id: str = Field(..., description="ID of the executed test case.")
    protocol: str = Field(..., description="Protocol used during execution.")
    status_code: int = Field(default=200, description="HTTP or RPC status code.")
    raw_response: str = Field(..., description="Raw text or JSON response from the agent.")
    structured_data: Optional[Dict[str, Any]] = Field(
        default=None, description="Parsed structured response if applicable."
    )
    tools_called: List[Dict[str, Any]] = Field(
        default_factory=list, description="Any tools that the agent attempted to execute."
    )
    response_time_ms: float = Field(
        default=0.0, description="Time taken to receive response in milliseconds."
    )
    error_message: Optional[str] = Field(
        default=None, description="Execution or connection error message, if any."
    )
    payload_sent: str = Field(..., description="Exact payload delivered.")
    executed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of execution in UTC.",
    )


class EvaluationResult(BaseModel):
    """Evaluation output analyzing whether an execution result exposed a vulnerability."""

    test_case_id: str = Field(..., description="ID of evaluated test case.")
    category: TestCategory = Field(..., description="Category evaluated.")
    is_vulnerable: bool = Field(
        ..., description="True if evidence indicates a vulnerability condition was met."
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score of the evaluation (0.0 to 1.0)."
    )
    rationale: str = Field(..., description="Detailed explanation of the determination.")
    evidence_snippets: List[str] = Field(
        default_factory=list,
        description="Direct quotes or data snippets proving the vulnerability.",
    )
    detector_name: str = Field(
        default="heuristic",
        description="Mechanism used: 'canary_detector', 'rule_engine', 'gemini_judge'.",
    )
    is_simulated: bool = Field(
        default=False,
        description="Whether this result originated from a simulated or mock agent.",
    )
