"""
Fetch.ai / Agentverse uAgent entry point.

Direct runner and alias for agentverse_agent.py.
Can be executed directly or imported into Agentverse.
"""

from agentverse_agent import (
    AuditRequest,
    AuditResponse,
    PingRequest,
    PingResponse,
    auditor_protocol,
    create_agentverse_auditor_agent,
)

if __name__ == "__main__":
    agent = create_agentverse_auditor_agent()
    agent.run()
