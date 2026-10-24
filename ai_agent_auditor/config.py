"""
Configuration module for the AI Agent Auditor.
"""

from typing import List, Optional
import os
from pydantic import BaseModel, ConfigDict, Field


class AuditorConfig(BaseModel):
    """Global configuration settings for the Agent Auditor."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Gemini API settings
    gemini_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY"),
        description="Google Gemini API key for test generation and evaluation.",
    )
    gemini_model: str = Field(
        default="gemini-2.5-flash",
        description="Gemini model name to use for generation and evaluation.",
    )
    gemini_temperature: float = Field(
        default=0.2,
        description="Temperature for Gemini test generation and evaluation.",
    )

    # Agentverse API settings
    agentverse_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("AGENTVERSE_API_KEY"),
        description="Optional Agentverse API key for authenticated registry lookups.",
    )
    agentverse_base_url: str = Field(
        default="https://agentverse.ai/v1",
        description="Base URL for the Agentverse / Almanac registry API.",
    )

    # Execution & Safety Controls
    require_human_approval: bool = Field(
        default=False,
        description="Whether tests require explicit approval before execution.",
    )
    request_timeout_seconds: float = Field(
        default=15.0,
        description="Timeout in seconds for agent communications.",
    )
    rate_limit_delay_seconds: float = Field(
        default=0.5,
        description="Delay in seconds between consecutive security tests.",
    )
    max_test_cases_per_run: int = Field(
        default=12,
        description="Maximum security test cases to generate and run per audit.",
    )
    allowed_protocols: List[str] = Field(
        default=["uagents", "mcp", "a2a", "mock"],
        description="Permitted protocols for interaction.",
    )

    # Reporting & Export
    output_dir: str = Field(
        default="./reports",
        description="Directory where reports are stored.",
    )
    destination_webhook_url: Optional[str] = Field(
        default_factory=lambda: os.getenv("AUDIT_DESTINATION_WEBHOOK"),
        description="Optional URL to POST completed audit reports to.",
    )



def get_default_config() -> AuditorConfig:
    """Return default configuration instance."""
    return AuditorConfig()
