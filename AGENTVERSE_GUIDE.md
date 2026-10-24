# Publishing AI Agent Auditor on Fetch.ai Agentverse 🌐

This guide walks you through publishing the **AI Agent Auditor** on [Agentverse](https://agentverse.ai), Fetch.ai's hosted agent platform and decentralized Almanac directory.

Once published, your auditor agent will have a public `agent1q...` address and can receive audit requests from any other agent or user in the Fetch.ai ecosystem.

---

## 🛠️ Publication Architecture

```
  ┌─────────────────────────────────────────────────────────────┐
  │                 Fetch.ai Agent Network                      │
  │     (DeltaV, Autonomous Agents, Chat Interfaces)            │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
                 Sends AuditRequest(target_address)
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │           AI Agent Auditor (Agentverse Service)             │
  │           Address: agent1q... (Registered on Almanac)       │
  ├─────────────────────────────────────────────────────────────┤
  │ 1. Fetches Target Agent Manifest & Tools                    │
  │ 2. Synthesizes Dynamic Probes via Gemini API                │
  │ 3. Executes Tests (uAgents / MCP / A2A)                     │
  │ 4. Validates Vulnerabilities & Calibrates Evidence          │
  │ 5. Returns Structured AuditResponse & Security Report       │
  └─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Option 1: Managed Agent in Agentverse Cloud (Recommended)

Host the agent directly on Agentverse's cloud infrastructure without needing your own server.

### Step 1: Sign in to Agentverse
1. Go to [https://agentverse.ai](https://agentverse.ai).
2. Sign in with your Google account, GitHub, or Web3 wallet.

### Step 2: Create a New Agent
1. In the left navigation, click **My Agents**.
2. Click the **+ New Agent** button in the top right.
3. Select **Blank Agent**.
4. Name your agent: `AI Agent Auditor`.

### Step 3: Add the Agent Code
1. Open the created agent editor in Agentverse.
2. In the `agent.py` tab, paste the code from [`agentverse_agent.py`](agentverse_agent.py).
3. If using dependencies, verify `uagents` is selected (included by default on Agentverse).

### Step 4: Configure Secrets
1. In the Agentverse editor, click the **Secrets** or **Environment Variables** tab.
2. Add a new secret:
   - **Key:** `GEMINI_API_KEY`
   - **Value:** *Your Google Gemini API Key*
3. (Optional) Add `AGENTVERSE_API_KEY` if you have one.

### Step 5: Start the Agent
1. Click the **Start** / **Run** button.
2. The console will display your agent's unique Fetch.ai address:
   ```text
   🛡️ AI Agent Auditor uAgent Started Successfully!
   Agent Name:    ai_agent_auditor
   Agent Address: agent1q2dx89x...
   Ready to receive AuditRequest messages across Fetch.ai network.
   ```

### Step 6: Publish Service & Register on Almanac
1. Navigate to the **Services** or **Almanac** tab for your agent in Agentverse.
2. Click **Register Service**.
3. Fill in the service details:
   - **Service Name:** `AI Agent Security Auditor`
   - **Description:** `Automated security assessment and vulnerability auditor for autonomous AI agents.`
   - **Protocols:** `AIAgentAuditorProtocol (v0.1.0)`
   - **Tags:** `security`, `audit`, `red-team`, `prompt-injection`, `mcp`
4. Click **Publish**. Your agent is now active and discoverable on Agentverse!

---

## 🖥️ Option 2: Local Agent with Agentverse Mailbox

Run the agent on your local machine or private cloud while routing external messages through Agentverse.

### Step 1: Obtain an Agentverse Mailbox Key
1. Go to **My Agents** on [https://agentverse.ai](https://agentverse.ai).
2. Click **Connect Local Agent** (or **Mailbox**).
3. Provide a name (`local-auditor`) and generate a **Mailbox API Key**.
4. Copy the generated mailbox key.

### Step 2: Launch Locally
In your PowerShell / terminal:

```powershell
$env:GEMINI_API_KEY = "your-gemini-api-key"
$env:AGENTVERSE_MAILBOX_KEY = "your-mailbox-api-key"
$env:AGENT_SECRET_SEED = "my_custom_unique_auditor_seed_phrase"

python agentverse_agent.py
```

Your local agent will register with the Agentverse Mailbox. Incoming requests from any agent on the internet will be routed safely to your local machine without needing public open ports or port forwarding!

---

## 📨 Interacting with Your Auditor Agent

Other agents on the Fetch.ai network can audit agents by sending the `AuditRequest` message:

```python
from uagents import Agent, Context, Model

class AuditRequest(Model):
    target_address: str
    auto_approve: bool = True
    categories: list[str] = []

class AuditResponse(Model):
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

client = Agent(name="audit_client", seed="client_seed_123")

AUDITOR_ADDRESS = "agent1q..."  # Your published auditor agent address

@client.on_event("startup")
async def send_audit(ctx: Context):
    # Request an audit of a target agent address
    await ctx.send(
        AUDITOR_ADDRESS,
        AuditRequest(target_address="agent1qvulnerable_demo_001", auto_approve=True)
    )

@client.on_message(model=AuditResponse)
async def handle_response(ctx: Context, sender: str, msg: AuditResponse):
    ctx.logger.info(f"Audit Finished: {msg.audit_id}")
    ctx.logger.info(f"Summary: {msg.summary}")
    ctx.logger.info(f"Confirmed Vulns: {msg.confirmed_vulnerabilities}")
    ctx.logger.info(f"Simulated Vulns: {msg.simulated_vulnerabilities}")

client.run()
```
