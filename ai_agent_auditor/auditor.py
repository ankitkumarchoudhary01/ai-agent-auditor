"""
Main AI Agent Auditor Orchestrator coordinating end-to-end security audits.
"""

from datetime import datetime, timezone
import logging
import time
from typing import List, Optional
import uuid

from ai_agent_auditor.config import AuditorConfig, get_default_config
from ai_agent_auditor.evaluator.engine import EvaluationEngine
from ai_agent_auditor.generator.test_generator import TestGenerator
from ai_agent_auditor.metadata.agentverse import AgentverseClient
from ai_agent_auditor.models.metadata import AgentEndpoint, AgentMetadata
from ai_agent_auditor.models.report import (
    AuditReport,
    FindingType,
    SecurityFinding,
)
from ai_agent_auditor.models.test_case import (
    ApprovalStatus,
    SecurityTestCase,
    TestCategory,
)
from ai_agent_auditor.protocols.registry import get_protocol_adapter
from ai_agent_auditor.reporter.exporter import ReportExporter

logger = logging.getLogger(__name__)


class AgentAuditor:
    """Orchestrator for automated security audits of autonomous AI agents."""

    def __init__(
        self,
        config: Optional[AuditorConfig] = None,
        metadata_client: Optional[AgentverseClient] = None,
        test_generator: Optional[TestGenerator] = None,
        evaluation_engine: Optional[EvaluationEngine] = None,
        exporter: Optional[ReportExporter] = None,
    ):
        self.config = config or get_default_config()
        self.metadata_client = metadata_client or AgentverseClient(self.config)
        self.test_generator = test_generator or TestGenerator(self.config)
        self.evaluation_engine = evaluation_engine or EvaluationEngine(self.config)
        self.exporter = exporter or ReportExporter(self.config)

    def audit_agent(
        self,
        address: str,
        auto_approve: bool = False,
        categories: Optional[List[TestCategory]] = None,
        export_reports: bool = True,
    ) -> AuditReport:
        """
        Execute an end-to-end security audit against an agent address.
        """
        audit_id = f"aud_{uuid.uuid4().hex[:10]}"
        logger.info("Starting security audit %s for agent address: %s", audit_id, address)

        # 1. Retrieve agent metadata and capabilities
        metadata = self.metadata_client.fetch_agent_metadata(address)
        logger.info("Retrieved metadata for '%s' (%s)", metadata.name, metadata.address)

        # 2. Automatically generate agent-specific security test cases using Gemini / capability analysis
        tests = self.test_generator.generate_tests_for_agent(metadata)
        if categories:
            tests = [t for t in tests if t.category in categories]

        # 3. Apply authorization controls
        if auto_approve or not self.config.require_human_approval:
            for t in tests:
                t.approval_status = ApprovalStatus.APPROVED

        approved_tests = [t for t in tests if t.approval_status == ApprovalStatus.APPROVED]
        logger.info(
            "Generated %d tests; %d approved for execution.", len(tests), len(approved_tests)
        )

        # 4. Execute approved tests across protocols and evaluate responses
        findings: List[SecurityFinding] = []
        executed_count = 0

        for test in approved_tests:
            # Rate limiting between test probes
            if executed_count > 0 and self.config.rate_limit_delay_seconds > 0:
                time.sleep(self.config.rate_limit_delay_seconds)

            # Match protocol and endpoint
            endpoint = self._resolve_endpoint_for_test(metadata, test)
            adapter = get_protocol_adapter(test.protocol, self.config)

            # Execute probe
            logger.debug("Executing test [%s] over protocol '%s'", test.id, test.protocol)
            result = adapter.execute(test, endpoint)
            executed_count += 1

            # Evaluate response
            eval_res = self.evaluation_engine.evaluate_test(test, result)
            if eval_res.is_vulnerable:
                finding = self.evaluation_engine.build_finding(test, result, eval_res)
                if finding:
                    findings.append(finding)

        # 5. Incorporate static manifest observations as unconfirmed warnings
        manifest_findings = self.evaluation_engine.build_metadata_warning_findings(metadata)
        findings.extend(manifest_findings)

        # 6. Collate statistics & audit summary
        is_simulation = metadata.registry_source in ["mock", "local"]
        confirmed_count = sum(
            1 for f in findings if f.finding_type == FindingType.CONFIRMED_VULNERABILITY
        )
        simulated_count = sum(
            1 for f in findings if f.finding_type == FindingType.SIMULATED_VULNERABILITY
        )
        warning_count = len(metadata.metadata_warnings)

        summary_text = self._build_executive_summary(
            target_name=metadata.name,
            total_tests=executed_count,
            confirmed=confirmed_count,
            simulated=simulated_count,
            warnings=warning_count,
            is_simulation=is_simulation,
        )

        report = AuditReport(
            audit_id=audit_id,
            target_address=metadata.address,
            target_name=metadata.name,
            target_protocols=metadata.protocols,
            timestamp=datetime.now(timezone.utc),
            total_tests_generated=len(tests),
            total_tests_executed=executed_count,
            confirmed_vulnerabilities_count=confirmed_count,
            simulated_vulnerabilities_count=simulated_count,
            metadata_warnings_count=warning_count,
            findings=findings,
            metadata_warnings=metadata.metadata_warnings,
            is_simulated_run=is_simulation,
            summary=summary_text,
            raw_metadata=metadata.model_dump(),
        )

        # 7. Export report to JSON, Markdown, and remote destination
        if export_reports:
            self.exporter.export(report)

        return report

    def _resolve_endpoint_for_test(
        self,
        metadata: AgentMetadata,
        test: SecurityTestCase,
    ) -> Optional[AgentEndpoint]:
        """Find matching endpoint for the test's target protocol."""
        for ep in metadata.endpoints:
            if ep.protocol.lower() == test.protocol.lower():
                return ep
        if metadata.endpoints:
            return metadata.endpoints[0]
        return None

    def _build_executive_summary(
        self,
        target_name: str,
        total_tests: int,
        confirmed: int,
        simulated: int,
        warnings: int,
        is_simulation: bool,
    ) -> str:
        """Compose clear summary respecting the distinction between live, simulated, and static findings."""
        env_str = "simulated local sandbox" if is_simulation else "live target environment"
        if confirmed > 0:
            posture = (
                f"**CRITICAL ACTION REQUIRED:** Security audit identified **{confirmed} CONFIRMED VULNERABILITIES** "
                f"on live agent '{target_name}'. Immediate remediation of broken boundaries and tool authorization is necessary."
            )
        elif simulated > 0:
            posture = (
                f"**SIMULATION FINDINGS:** Auditing within the {env_str} uncovered **{simulated} simulated vulnerabilities**. "
                f"In accordance with auditor policy, simulated results are recorded for testing calibration and are not considered confirmed on production systems."
            )
        else:
            posture = (
                f"**SECURE POSTURE:** Agent '{target_name}' demonstrated robust defense mechanisms against all {total_tests} "
                "executed attack probes, cleanly enforcing instruction boundaries and rejecting unauthorized invocations."
            )

        warning_note = (
            f" Additionally, {warnings} static manifest observations were logged for advisory review."
            if warnings > 0
            else ""
        )

        return f"{posture}{warning_note}"
