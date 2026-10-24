"""
Command-line interface (CLI) for the AI Agent Auditor.
"""

import sys
from typing import List, Optional
import click
from ai_agent_auditor.auditor import AgentAuditor
from ai_agent_auditor.config import AuditorConfig
from ai_agent_auditor.metadata.registry import list_registered_mock_agents
from ai_agent_auditor.models.test_case import TestCategory


@click.group()
@click.version_option(version="0.1.0")
def main():
    """AI Agent Auditor - Automated Security Testing Framework for Autonomous Agents."""
    pass


@main.command(name="audit")
@click.option(
    "--address",
    "-a",
    required=True,
    help="Agent address to audit (Agentverse address, or local mock ID like 'agent1qvulnerable_demo_001').",
)
@click.option(
    "--auto-approve",
    is_flag=True,
    default=False,
    help="Automatically approve all generated security test cases for execution.",
)
@click.option(
    "--category",
    "-c",
    type=click.Choice([c.value for c in TestCategory], case_sensitive=False),
    multiple=True,
    help="Filter security test categories to execute (repeatable).",
)
@click.option(
    "--model",
    "-m",
    default="gemini-2.5-flash",
    help="Gemini model identifier for test generation and evaluation.",
)
@click.option(
    "--output-dir",
    "-o",
    default="./reports",
    help="Directory to save JSON and Markdown security reports.",
)
@click.option(
    "--destination",
    "-d",
    default=None,
    help="Optional HTTP webhook destination URL to transmit completed audit reports.",
)
def audit_command(
    address: str,
    auto_approve: bool,
    category: List[str],
    model: str,
    output_dir: str,
    destination: Optional[str],
):
    """Run an automated security audit against an agent address."""
    click.echo(click.style(f"\n[+] Initializing AI Agent Auditor for: {address}", fg="cyan", bold=True))

    config = AuditorConfig(
        gemini_model=model,
        output_dir=output_dir,
        destination_webhook_url=destination,
        require_human_approval=not auto_approve,
    )

    auditor = AgentAuditor(config=config)

    cat_enums = [TestCategory(c) for c in category] if category else None

    try:
        report = auditor.audit_agent(
            address=address,
            auto_approve=auto_approve,
            categories=cat_enums,
            export_reports=True,
        )

        click.echo(click.style(f"\n[OK] Audit Complete: {report.audit_id}", fg="green", bold=True))
        click.echo(f"  Target: {report.target_name} ({report.target_address})")
        click.echo(f"  Total Probes Executed: {report.total_tests_executed}")
        click.echo(f"  Confirmed Vulnerabilities: {report.confirmed_vulnerabilities_count}")
        click.echo(f"  Simulated Vulnerabilities: {report.simulated_vulnerabilities_count}")
        click.echo(f"  Static Manifest Warnings: {report.metadata_warnings_count}")
        click.echo(f"\nReports saved in: {output_dir}/")
        click.echo(f"  JSON:     audit_{report.audit_id}.json")
        click.echo(f"  Markdown: audit_{report.audit_id}.md")

        if report.findings:
            click.echo(click.style(f"\nDetailed Findings Summary ({len(report.findings)} items):", bold=True))
            for f in report.findings:
                sev_color = "red" if f.severity.value in ["critical", "high"] else "yellow"
                click.echo(f"  - [{click.style(f.severity.value.upper(), fg=sev_color)}] {f.title} ({f.finding_type.value})")

    except Exception as exc:
        click.echo(click.style(f"\n[-] Audit encountered error: {exc}", fg="red"), err=True)
        sys.exit(1)


@main.command(name="list-mock-agents")
def list_mock_agents():
    """List registered local mock agents available for testing."""
    agents = list_registered_mock_agents()
    click.echo(click.style(f"\nRegistered Local Mock Agents ({len(agents)}):", bold=True, fg="cyan"))
    for addr, meta in agents.items():
        click.echo(f"\n- Address: {click.style(addr, fg='green')}")
        click.echo(f"  Name: {meta.name}")
        click.echo(f"  Description: {meta.description}")
        click.echo(f"  Protocols: {', '.join(meta.protocols)}")
        click.echo(f"  Capabilities: {', '.join(c.name for c in meta.capabilities)}")


@main.command(name="test-mock")
@click.option(
    "--hardened",
    is_flag=True,
    default=False,
    help="Audit hardened agent instead of vulnerable demo agent.",
)
def test_mock_command(hardened: bool):
    """Run a quick end-to-end audit on local mock agent."""
    addr = "agent1qhardened_demo_002" if hardened else "agent1qvulnerable_demo_001"
    click.echo(click.style(f"\nRunning local mock audit against: {addr}", fg="cyan", bold=True))
    config = AuditorConfig(output_dir="./reports", require_human_approval=False)
    auditor = AgentAuditor(config=config)
    report = auditor.audit_agent(address=addr, auto_approve=True)

    click.echo(click.style(f"\nAudit Finished: {report.audit_id}", fg="green"))
    click.echo(f"Executive Summary:\n{report.summary}")


if __name__ == "__main__":
    main()
