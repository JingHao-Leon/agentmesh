"""Agent 运行时。启动方式 python -m agentmesh.agent --id <id> --capabilities a,b"""

from .runtime import Agent, AgentError, main

__all__ = ["Agent", "AgentError", "main"]