"""
Markdown template generation for the AI Agent Security Audit Report.
"""

from ai_agent_auditor.models.report import AuditReport, FindingType, Severity

SEVERITY_BADGES = {
    Severity.CRITICAL: "[CRITICAL]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MEDIUM]",
    Severity.LOW: "[LOW]",
    Severity.INFO: "[INFO]",
}


def generate_markdown_report(report: AuditReport) -> str:
    """Render a comprehensive, professional Markdown report from an AuditReport model."""
    lines = []
    lines.append(f"# AI Agent Security Audit Report")
    lines.append("")
    lines.append(f"**Audit ID:** `{report.audit_id}`  ")
    lines.append(f"**Target Agent Address:** `{report.target_address}`  ")
    lines.append(f"**Target Agent Name:** {report.target_name}  ")
    lines.append(f"**Protocols Tested:** {', '.join(report.target_protocols) or 'None'}  ")
    lines.append(f"**Audit Timestamp (UTC):** {report.timestamp.isoformat()}  ")
    lines.append(f"**Simulation Environment:** {'Yes (Local Mock / Simulation)' if report.is_simulated_run else 'No (Live Network Target)'}  ")
    lines.append("")

    # Executive Summary Card
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(report.summary)
    lines.append("")

    # Summary Table
    lines.append("| Metric | Count | Description |")
    lines.append("|---|---|---|")
    lines.append(f"| **Total Tests Generated** | {report.total_tests_generated} | Number of capability-tailored security probes created |")
    lines.append(f"| **Total Tests Executed** | {report.total_tests_executed} | Authorized tests executed against endpoint |")
    lines.append(f"| **Confirmed Vulnerabilities** | **{report.confirmed_vulnerabilities_count}** | Dynamically validated on live agent (*zero assumptions*) |")
    lines.append(f"| **Simulated Vulnerabilities** | **{report.simulated_vulnerabilities_count}** | Validated during mock or simulated agent execution |")
    lines.append(f"| **Static Metadata Warnings** | {report.metadata_warnings_count} | Unconfirmed manifest / permission observations |")
    lines.append("")

    # Static Manifest Observations Section
    if report.metadata_warnings:
        lines.append("## Static Metadata Observations")
        lines.append("> [!NOTE]")
        lines.append("> The following observations were derived from static analysis of the agent's manifest and advertised capabilities.")
        lines.append("> **Important:** Under security auditor policy, metadata warnings are never treated as confirmed vulnerabilities without dynamic proof.")
        lines.append("")
        for w in report.metadata_warnings:
            lines.append(f"- [OBSERVATION] {w}")
        lines.append("")

    # Findings Section
    lines.append("## Detailed Security Findings")
    lines.append("")

    if not report.findings:
        lines.append("**No vulnerabilities detected.** The agent successfully enforced boundary checks and safety directives across all executed probes.")
        lines.append("")
    else:
        for finding in report.findings:
            sev_badge = SEVERITY_BADGES.get(finding.severity, finding.severity.value)
            conf_percent = f"{int(finding.confidence * 100)}%"

            lines.append(f"### [{finding.id}] {finding.title}")
            lines.append("")
            lines.append(f"- **Severity:** {sev_badge}")
            lines.append(f"- **Category:** `{finding.category.value}`")
            lines.append(f"- **Finding Type:** `{finding.finding_type.value}`")
            lines.append(f"- **Confidence Score:** `{conf_percent}`")
            if finding.affected_tool_or_protocol:
                lines.append(f"- **Affected Component:** `{finding.affected_tool_or_protocol}`")
            lines.append("")
            lines.append(f"**Description:**")
            lines.append(f"{finding.description}")
            lines.append("")

            # Reproduction steps
            lines.append("**Reproduction Steps:**")
            lines.append("```text")
            for step in finding.reproduction_steps:
                lines.append(step)
            lines.append("```")
            lines.append("")

            # Evidence
            if finding.evidence:
                lines.append("**Empirical Evidence Captured:**")
                lines.append("```text")
                for ev in finding.evidence:
                    lines.append(ev)
                lines.append("```")
                lines.append("")

            # Remediation
            lines.append("**Remediation Recommendations:**")
            lines.append(f"> {finding.remediation}")
            lines.append("")
            lines.append("---")
            lines.append("")

    # Methodology & Disclaimer footer
    lines.append("## Audit Methodology & Disclaimer")
    lines.append(
        "This automated security evaluation was conducted according to responsible disclosure guidelines. "
        "Test cases were synthesized to verify boundary isolation, prompt injection resilience, capability authorization, "
        "and data confidentiality. Simulated results and manifest observations are clearly demarcated to prevent false positives."
    )
    lines.append("")

    return "\n".join(lines)
