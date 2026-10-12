"""Agent 进程入口:python -m agentmesh.agent --id <id> --capabilities a,b"""

from .runtime import main

if __name__ == "__main__":
    raise SystemExit(main())