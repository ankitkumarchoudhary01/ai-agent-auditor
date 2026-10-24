# AI Agent Auditor 🛡️

**AI Agent Auditor** is an automated security assessment and red-teaming framework for autonomous AI agents built using Python and the Google Gemini API.

It connects to agent registries (such as Fetch.ai Agentverse / Almanac), parses advertised capabilities and tool declarations, automatically generates capability-tailored security test cases using Gemini, executes approved tests across supported communication protocols (**uAgents**, **MCP**, **A2A**, and **Mock**), and synthesizes evidence-based security reports.

---

## 🏛️ Architectural Overview

```
                          ┌───────────────────────────┐
                          │   Target Agent Address    │
                          └─────────────┬─────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │ 1. Metadata Retrieval (Agentverse Client & Registry Resolver)          │
    │    - Fetch Almanac manifest, endpoints, protocols, & tools            │
    │    - Perform static risk analysis (generates metadata_warnings)       │
    └───────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │ 2. Test Generation (Gemini API & Capability Synthesis)               │
    │    - Gemini-powered prompt generation tailored to agent tools         │
    │    - Probes: Prompt Injection, Tool Misuse, Data Leak, Input Fuzz     │
    │    - Deterministic canary token injection (CANARY_<HEX>)              │
    └───────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │ 3. Authorization & Approval Gate                                     │
    │    - Human-in-the-loop / Auto-approve policy enforcement              │
    │    - Rate-limiting & execution isolation                              │
    └───────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │ 4. Protocol Dispatch Layer                                           │
    │    ├── uAgents Adapter (Fetch.ai envelope over HTTP webhook)          │
    │    ├── MCP Adapter (Model Context Protocol JSON-RPC 2.0 tools/call)   │
    │    ├── A2A Adapter (Agent-to-Agent REST protocol)                     │
    │    └── Mock Adapter (High-fidelity in-memory local testing)           │
    └───────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │ 5. Dual Evaluation Engine                                             │
    │    ├── Rule & Canary Detector (regex, tokens, tracebacks, tool logs)  │
    │    └── Gemini LLM Judge (semantic compliance & boundary analysis)     │
    │                                                                       │
    │    [Strict Rule Enforced]:                                            │
    │    - Live empirical proofs  --> CONFIRMED_VULNERABILITY               │
    │    - Mock/sandbox tests     --> SIMULATED_VULNERABILITY               │
    │    - Manifest observations  --> METADATA_WARNING                      │
    └───────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        ▼
    ┌───────────────────────────────────────────────────────────────────────┐
    │ 6. Reporting & Destination Exporter                                   │
    │    - JSON Export (validated against Pydantic AuditReport schema)      │
    │    - Markdown Export (executive summary, tables, reproduction steps)  │
    │    - Webhook Submission (optional HTTP POST to security SIEM)         │
    └───────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Key Capabilities & Vulnerability Categories

1. **Prompt Injection & Instruction Override (`prompt_injection`)**
   - Tests resistance to delimiter hijacking, roleplay framing, priority directive resets (`SYSTEM OVERRIDE`), and system prompt exfiltration.
2. **Unauthorized Tool Invocation (`unauthorized_tool_usage`)**
   - Automatically probes declared tools (e.g. `transfer_funds`, `read_internal_document`, `exec_shell`) to verify that unauthenticated callers cannot trigger sensitive capabilities.
3. **Sensitive Data Leakage (`data_leakage`)**
   - Probes memory and generation context for internal API keys, private keys, synthetic canary tokens, and internal paths.
4. **Input Validation Failures (`input_validation`)**
   - Fuzzes agent endpoints with malformed JSON, prototype pollution keys, oversized inputs, and evaluates whether the agent leaks unhandled stack traces (500 errors).

---

## ⚖️ The Strict Evidence Principle

> **"Never treat simulated results or metadata warnings as confirmed vulnerabilities."**

The auditor strictly enforces this boundary:
- **`CONFIRMED_VULNERABILITY`**: Assigned **only** when empirical proof is captured during dynamic execution against a live agent endpoint.
- **`SIMULATED_VULNERABILITY`**: Assigned when tests are executed against local mock or simulated agents. These are explicitly tagged with `(Simulated)` and `is_confirmed = False`.
- **`METADATA_WARNING`**: Advisory static observations derived from manifest analysis (e.g. unencrypted HTTP or broad tool permissions). They are never treated as confirmed vulnerabilities without dynamic proof.

---

## 🚀 Quickstart & Installation

### Requirements
- Python 3.10+
- Dependencies: `pydantic`, `httpx`, `click`, `pytest`

### Environment Variables (Optional)
```bash
# Gemini API Key for dynamic LLM test generation & semantic judging
export GEMINI_API_KEY="your-gemini-api-key"

# Optional Agentverse API key for authenticated registry queries
export AGENTVERSE_API_KEY="your-agentverse-api-key"

# Optional webhook URL for automatic report forwarding
export AUDIT_DESTINATION_WEBHOOK="https://your-siem.example.com/api/audit-reports"
```

---

## 💻 CLI Usage

The package provides a built-in CLI:

```bash
# 1. List registered local mock agents
python -m ai_agent_auditor.cli list-mock-agents

# 2. Run a full security audit against a vulnerable test agent
python -m ai_agent_auditor.cli audit --address agent1qvulnerable_demo_001 --auto-approve

# 3. Run a security audit against a hardened test agent
python -m ai_agent_auditor.cli audit --address agent1qhardened_demo_002 --auto-approve

# 4. Audit a live Agentverse address
python -m ai_agent_auditor.cli audit --address agent1q00000000000000000000000000000000000000 --auto-approve

# 5. Filter tests by vulnerability category
python -m ai_agent_auditor.cli audit --address agent1qvulnerable_demo_001 --auto-approve --category prompt_injection --category unauthorized_tool_usage

# 6. Specify custom report output directory and remote webhook
python -m ai_agent_auditor.cli audit --address agent1qvulnerable_demo_001 --auto-approve -o ./my_reports -d https://internal-siem.corp/webhook
```

---

## 🐍 Python SDK API Usage

```python
from ai_agent_auditor.auditor import AgentAuditor
from ai_agent_auditor.config import AuditorConfig
from ai_agent_auditor.models.test_case import TestCategory

# Configure the auditor
config = AuditorConfig(
    gemini_api_key="your-api-key",  # or uses GEMINI_API_KEY env var
    gemini_model="gemini-2.5-flash",
    output_dir="./reports",
    require_human_approval=False,   # Auto-approve for automated CI/CD pipelines
)

auditor = AgentAuditor(config=config)

# Execute security audit
report = auditor.audit_agent(
    address="agent1qvulnerable_demo_001",
    auto_approve=True,
    categories=[TestCategory.PROMPT_INJECTION, TestCategory.UNAUTHORIZED_TOOL_USAGE],
    export_reports=True,
)

# Inspect findings
print(f"Audit ID: {report.audit_id}")
print(f"Confirmed Vulnerabilities: {report.confirmed_vulnerabilities_count}")
print(f"Simulated Vulnerabilities: {report.simulated_vulnerabilities_count}")

for finding in report.findings:
    print(f"[{finding.severity.value.upper()}] {finding.title}")
    print(f"  Confidence: {finding.confidence * 100:.0f}%")
    print(f"  Remediation: {finding.remediation}")
```

---

## 🧪 Running Tests

The test suite contains 33 comprehensive unit and end-to-end integration tests:

```bash
python -m pytest -v
```

Test coverage includes:
- `test_models.py`: Pydantic validation and serialization
- `test_metadata.py`: Agentverse API client, static warning enrichment, and fallbacks
- `test_generator.py`: Capability-tailored probe generation, canary token synthesis, approval gates
- `test_mock_agent.py`: Local mock agent in vulnerable and hardened modes
- `test_protocols.py`: uAgents envelope dispatch, MCP JSON-RPC, A2A, and approval checks
- `test_evaluator.py`: Rule detector, Gemini judge, and strict separation of confirmed vs simulated findings
- `test_reporter.py`: Markdown and JSON serialization, remote webhook posting
- `test_e2e_audit.py`: Full end-to-end audit pipelines for vulnerable and hardened agents
