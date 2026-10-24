"""
Agentverse-Compatible uAgent Service.

This script exposes the AI Agent Auditor as an autonomous uAgent that can be:
1. Deployed directly in the Agentverse Cloud IDE (https://agentverse.ai) as a Managed Agent.
2. Run locally and connected to Agentverse via an Agentverse Mailbox API key.

Other agents across Fetch.ai network can query this agent to audit themselves or other agents!
"""

import asyncio
import json
import os
from typing import List, Optional
from uagents import Agent, Context, Model, Protocol
from ai_agent_auditor.auditor import AgentAuditor
from ai_agent_auditor.config import AuditorConfig
from ai_agent_auditor.models.test_case import TestCategory


# --- Protocol Message Models ---
class AuditRequest(Model):
    """Request message to audit an agent."""
    target_address: str
    auto_approve: bool = True
    categories: List[str] = []


class AuditResponse(Model):
    """Response containing security audit results and summary."""
    audit_id: str
    target_address: str
    target_name: str
    status: str
    summary: str
    confirmed_vulnerabilities: int
    simulated_vulnerabilities: int
    metadata_warnings: int
    findings_count: int
    report_json: str


class PingRequest(Model):
    """Simple ping check for agent health."""
    message: str = "ping"


class PingResponse(Model):
    """Health confirmation."""
    status: str
    agent_address: str
    version: str


# --- Auditor Service Protocol ---
auditor_protocol = Protocol(name="AIAgentAuditorProtocol", version="0.1.0")


@auditor_protocol.on_message(model=PingRequest, replies=PingResponse)
async def handle_ping(ctx: Context, sender: str, msg: PingRequest):
    ctx.logger.info(f"Ping received from {sender}")
    await ctx.send(
        sender,
        PingResponse(
            status="online",
            agent_address=ctx.agent.address,
            version="0.1.0",
        ),
    )


@auditor_protocol.on_message(model=AuditRequest, replies=AuditResponse)
async def handle_audit(ctx: Context, sender: str, msg: AuditRequest):
    ctx.logger.info(f"Received audit request for '{msg.target_address}' from '{sender}'")

    try:
        config = AuditorConfig(
            gemini_api_key=os.getenv("GEMINI_API_KEY"),
            output_dir="./reports",
            require_human_approval=not msg.auto_approve,
        )
        auditor = AgentAuditor(config=config)

        cat_enums = None
        if msg.categories:
            cat_enums = [TestCategory(c) for c in msg.categories if c in [x.value for x in TestCategory]]

        report = auditor.audit_agent(
            address=msg.target_address,
            auto_approve=msg.auto_approve,
            categories=cat_enums,
            export_reports=True,
        )

        response = AuditResponse(
            audit_id=report.audit_id,
            target_address=report.target_address,
            target_name=report.target_name,
            status="completed",
            summary=report.summary,
            confirmed_vulnerabilities=report.confirmed_vulnerabilities_count,
            simulated_vulnerabilities=report.simulated_vulnerabilities_count,
            metadata_warnings=report.metadata_warnings_count,
            findings_count=len(report.findings),
            report_json=report.model_dump_json(),
        )

        ctx.logger.info(
            f"Audit completed: {report.audit_id}. Confirmed={report.confirmed_vulnerabilities_count}, "
            f"Simulated={report.simulated_vulnerabilities_count}. Sending response to {sender}"
        )
        await ctx.send(sender, response)

    except Exception as exc:
        ctx.logger.error(f"Error executing audit: {exc}")
        await ctx.send(
            sender,
            AuditResponse(
                audit_id="error",
                target_address=msg.target_address,
                target_name="Unknown",
                status=f"failed: {str(exc)}",
                summary=f"Audit execution failed: {str(exc)}",
                confirmed_vulnerabilities=0,
                simulated_vulnerabilities=0,
                metadata_warnings=0,
                findings_count=0,
                report_json="{}",
            ),
        )


# --- Factory & Standalone Runner ---
def create_agentverse_auditor_agent(
    name: str = "ai_agent_auditor",
    seed: Optional[str] = None,
    mailbox: Optional[str] = None,
    port: int = 8000,
    endpoint: Optional[str] = None,
) -> Agent:
    """Create and configure the Agentverse-compatible uAgent."""
    # Ensure event loop exists (required on Python 3.12+)
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    agent_seed = seed or os.getenv("AGENT_SECRET_SEED", "ai_agent_auditor_secure_seed_phrase_9921")
    agent_mailbox = mailbox or os.getenv("AGENTVERSE_MAILBOX_KEY")

    agent_kwargs = {
        "name": name,
        "seed": agent_seed,
        "loop": loop,
    }

    if agent_mailbox:
        # Connect to Agentverse Mailbox for serverless hosting
        agent_kwargs["mailbox"] = agent_mailbox
    else:
        # Standard local network endpoint
        agent_kwargs["port"] = port
        if endpoint:
            agent_kwargs["endpoint"] = [endpoint]

    agent = Agent(**agent_kwargs)
    agent.include(auditor_protocol)

    @agent.on_event("startup")
    async def startup(ctx: Context):
        ctx.logger.info("=" * 60)
        ctx.logger.info("🛡️ AI Agent Auditor uAgent Started Successfully!")
        ctx.logger.info(f"Agent Name:    {ctx.agent.name}")
        ctx.logger.info(f"Agent Address: {ctx.agent.address}")
        ctx.logger.info(f"Mailbox Active: {bool(agent_mailbox)}")
        ctx.logger.info("Ready to receive AuditRequest messages across Fetch.ai network.")
        ctx.logger.info("=" * 60)

    return agent


if __name__ == "__main__":
    agent = create_agentverse_auditor_agent()
    agent.run()
