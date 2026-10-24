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

import os
from uagents_core.utils.registration import (
    register_chat_agent,
    RegistrationRequestCredentials,
)

register_chat_agent(
    "AI Agent Auditor",
    "https://github.com/ankitkumarchoudhary01/ai-agent-auditor/blob/main/agent.py",
    active=True,
    credentials=RegistrationRequestCredentials(
        agentverse_api_key=os.environ["AGENTVERSE_KEY"],
        agent_seed_phrase=os.environ["AGENT_SEED_PHRASE"],        
    ),
)

if __name__ == "__main__":
    agent = create_agentverse_auditor_agent()
    agent.run()
