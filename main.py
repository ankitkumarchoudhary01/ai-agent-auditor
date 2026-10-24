"""
Main entry point for AI Agent Auditor.

Usage:
    python main.py audit --address agent1qvulnerable_demo_001 --auto-approve
    python main.py list-mock-agents
"""

from ai_agent_auditor.cli import main
from ai_agent_auditor.auditor import AgentAuditor
from ai_agent_auditor.config import AuditorConfig

if __name__ == "__main__":
    main()
