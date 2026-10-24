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
        agentverse_api_key=os.environ["eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3OTU0MTQxOTUsImlhdCI6MTc5MjgyMjE5NSwiaXNzIjoiZmV0Y2guYWkiLCJqdGkiOiI2MDA2ODc3MzFkMTdlMWUxZDdkMzk0MGMiLCJzY29wZSI6ImF2Iiwic3ViIjoiYmI2N2E4Mjc0ZDAyNTc3ZGQ4ODYzY2MzMmZlNjhiNzg5OTBlOTdkNGNmMGM0NzVlIn0.VQY3coDmwB-YecWAF18PJciN-UMv3JLanee8SlyNjVTyoJcxHE2fkq-75_652oHCbRNoENAcT2LYqTq1LhjDGM5kDXtDf30O4H-7iNzr7cx6_Jo4w13Q5rJjq3o-aZMxOM_RdIdF-OFzDBwxBFxJa1OSXTbuYsKmyqWnfHlcTywy6dEcX0lIUDvaRi07KUJ7u_2OHwfRmQEKebRPLQNsCmV5K4x7mwyQXmG5PFm38QtkkWmzSQtTvt4f2FOv9WEVoMDVlgioZY6R7hULM5EQAzEaadayjBBR49fmcwSYRx4O7ZCa1MG95uILoJXbObmRb2EcpW5Y_QYifkFswMaGsg"],
        agent_seed_phrase=os.environ["maple-river-82-silver-cloud-fox-47"],        
    ),
)

if __name__ == "__main__":
    agent = create_agentverse_auditor_agent()
    agent.run()
