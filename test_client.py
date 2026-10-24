"""
Local Test Client for querying the AI Agent Auditor uAgent.

Demonstrates Agent-to-Agent (A2A) communication:
1. Initializes a client agent on port 8001.
2. Sends an AuditRequest to the Auditor agent running on port 8000.
3. Receives and displays the AuditResponse.

Usage:
    Terminal 1: python agent.py
    Terminal 2: python test_client.py
"""

import asyncio
from uagents import Agent, Context
from agentverse_agent import AuditRequest, AuditResponse

# Initialize test client on separate port (8001)
client = Agent(
    name="auditor_test_client",
    seed="auditor_test_client_seed_9981",
    port=8001,
    endpoint=["http://127.0.0.1:8001/submit"],
)

# Address of the auditor agent created by 'agent.py'
AUDITOR_SEED = "ai_agent_auditor_secure_seed_phrase_9921"
# Compute target address matching the default seed
from uagents.crypto import Identity
auditor_identity = Identity.from_seed(AUDITOR_SEED, 0)
AUDITOR_ADDRESS = auditor_identity.address


@client.on_event("startup")
async def send_audit_request(ctx: Context):
    ctx.logger.info("=" * 60)
    ctx.logger.info("Client Agent Started!")
    ctx.logger.info(f"Target Auditor Address: {AUDITOR_ADDRESS}")
    ctx.logger.info("Sending AuditRequest for 'agent1qvulnerable_demo_001'...")
    ctx.logger.info("=" * 60)

    # Allow 1 second for servers to settle
    await asyncio.sleep(1.0)

    await ctx.send(
        AUDITOR_ADDRESS,
        AuditRequest(
            target_address="agent1qvulnerable_demo_001",
            auto_approve=True,
            categories=["prompt_injection", "unauthorized_tool_usage"],
        ),
    )


@client.on_message(model=AuditResponse)
async def handle_audit_response(ctx: Context, sender: str, msg: AuditResponse):
    ctx.logger.info("=" * 60)
    ctx.logger.info(f"Received AuditResponse from: {sender}")
    ctx.logger.info(f"Audit ID:                  {msg.audit_id}")
    ctx.logger.info(f"Target Agent:              {msg.target_name} ({msg.target_address})")
    ctx.logger.info(f"Status:                    {msg.status}")
    ctx.logger.info(f"Confirmed Vulnerabilities: {msg.confirmed_vulnerabilities}")
    ctx.logger.info(f"Simulated Vulnerabilities: {msg.simulated_vulnerabilities}")
    ctx.logger.info(f"Metadata Warnings:         {msg.metadata_warnings}")
    ctx.logger.info(f"Total Findings Count:      {msg.findings_count}")
    ctx.logger.info(f"Summary:                   {msg.summary}")
    ctx.logger.info("=" * 60)


if __name__ == "__main__":
    client.run()
