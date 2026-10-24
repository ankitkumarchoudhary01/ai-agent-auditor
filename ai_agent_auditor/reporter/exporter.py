"""
Report Exporter for JSON, Markdown, and remote webhook dispatch.
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, Optional, Tuple
import httpx
from ai_agent_auditor.config import AuditorConfig
from ai_agent_auditor.models.report import AuditReport
from ai_agent_auditor.reporter.templates import generate_markdown_report

logger = logging.getLogger(__name__)


class ReportExporter:
    """Handles serializing and exporting security reports to local files and remote endpoints."""

    def __init__(self, config: AuditorConfig, http_client: Optional[httpx.Client] = None):
        self.config = config
        self.http_client = http_client or httpx.Client(timeout=config.request_timeout_seconds)

    def export(self, report: AuditReport) -> Tuple[Path, Path, Optional[bool]]:
        """
        Export report to JSON and Markdown, and submit to remote destination if configured.
        Returns (json_path, markdown_path, submission_success).
        """
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        filename_base = f"audit_{report.audit_id}"
        json_path = output_dir / f"{filename_base}.json"
        md_path = output_dir / f"{filename_base}.md"

        # 1. Export JSON
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
        logger.info("JSON report exported to: %s", json_path)

        # 2. Export Markdown
        markdown_content = generate_markdown_report(report)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        logger.info("Markdown report exported to: %s", md_path)

        # 3. Submit to remote destination if configured
        submission_success = None
        if self.config.destination_webhook_url:
            submission_success = self._submit_to_destination(report)

        return json_path, md_path, submission_success

    def _submit_to_destination(self, report: AuditReport) -> bool:
        """Transmit completed audit report to remote webhook destination."""
        url = self.config.destination_webhook_url
        if not url:
            return False

        logger.info("Submitting audit report %s to destination: %s", report.audit_id, url)
        try:
            payload = json.loads(report.model_dump_json())
            response = self.http_client.post(
                url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "AI-Agent-Auditor/1.0",
                },
            )
            if response.status_code in (200, 201, 202, 204):
                logger.info("Successfully delivered audit report to %s", url)
                return True
            else:
                logger.warning(
                    "Remote destination returned status %d: %s",
                    response.status_code,
                    response.text[:200],
                )
                return False
        except Exception as exc:
            logger.error("Failed to submit report to destination %s: %s", url, exc)
            return False
