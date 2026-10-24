"""
Google Gemini API Client for security test generation and evaluation.
"""

import json
import logging
import time
from typing import Any, Dict, Optional
import httpx
from ai_agent_auditor.config import AuditorConfig

logger = logging.getLogger(__name__)


class GeminiClient:
    """Client for Google Gemini API with JSON generation, retries, and offline fallback."""

    def __init__(self, config: AuditorConfig, http_client: Optional[httpx.Client] = None):
        self.config = config
        self.api_key = config.gemini_api_key
        self.model = config.gemini_model
        self.http_client = http_client or httpx.Client(timeout=config.request_timeout_seconds * 2)
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"

    @property
    def is_available(self) -> bool:
        """Check if Gemini API key is configured."""
        return bool(self.api_key and len(self.api_key.strip()) > 5)

    def generate_content(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        json_output: bool = True,
        max_retries: int = 3,
    ) -> str:
        """Generate content from Gemini model with retries and structured output."""
        if not self.is_available:
            raise RuntimeError(
                "GEMINI_API_KEY is not configured. Set the environment variable or pass config."
            )

        url = f"{self.base_url}/{self.model}:generateContent?key={self.api_key}"

        request_body: Dict[str, Any] = {
            "contents": [
                {
                    "parts": [{"text": prompt}],
                    "role": "user",
                }
            ],
            "generationConfig": {
                "temperature": self.config.gemini_temperature,
            },
        }

        if system_instruction:
            request_body["systemInstruction"] = {
                "parts": [{"text": system_instruction}]
            }

        if json_output:
            request_body["generationConfig"]["responseMimeType"] = "application/json"

        last_error = None
        for attempt in range(max_retries):
            try:
                response = self.http_client.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json=request_body,
                )
                if response.status_code == 200:
                    data = response.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            return parts[0].get("text", "")
                    return ""
                elif response.status_code in (429, 500, 502, 503, 504):
                    logger.warning(
                        "Gemini API returned status %d on attempt %d. Retrying...",
                        response.status_code,
                        attempt + 1,
                    )
                    time.sleep(1.5 * (attempt + 1))
                else:
                    error_msg = f"Gemini API error {response.status_code}: {response.text}"
                    logger.error(error_msg)
                    raise RuntimeError(error_msg)
            except (httpx.RequestError, httpx.TimeoutException) as exc:
                last_error = exc
                logger.warning("Network error calling Gemini API: %s. Retrying...", exc)
                time.sleep(1.5 * (attempt + 1))

        raise RuntimeError(f"Gemini API failed after {max_retries} attempts: {last_error}")

    def generate_json(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
    ) -> Any:
        """Generate and parse structured JSON from Gemini."""
        raw_text = self.generate_content(
            prompt=prompt,
            system_instruction=system_instruction,
            json_output=True,
        )
        if not raw_text:
            return None
        # Handle cases where model wraps in markdown json fences
        cleaned = raw_text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        return json.loads(cleaned.strip())
