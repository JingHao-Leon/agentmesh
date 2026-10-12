"""Hub:中心服务。启动方式 python -m agentmesh.hub"""

from .app import create_app

__all__ = ["create_app"]