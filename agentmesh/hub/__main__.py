"""中心服务入口:python -m agentmesh.hub [--host H --port P]"""

from __future__ import annotations

import argparse

import uvicorn

from .app import create_app
from ..config import get_settings


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(prog="python -m agentmesh.hub", description="启动 AgentMesh 中心")
    parser.add_argument("--host", default=settings.host)
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--reload", action="store_true", help="开发模式热重载")
    parser.add_argument(
        "--log-level", default="warning", choices=["critical", "error", "warning", "info", "debug"]
    )
    args = parser.parse_args()

    settings.ensure_dirs()
    print(f"数据目录:{settings.data_dir}")
    print(f"看板地址:http://{args.host}:{args.port}/")
    print(f"API 文档:http://{args.host}:{args.port}/docs")
    uvicorn.run(
        create_app(),
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())