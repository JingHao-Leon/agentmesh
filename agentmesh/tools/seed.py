"""灌一批演示任务。

这些任务不是"演示专用数据",就是普通任务 —— 区别只在 required_capability
不同,不同能力的 Agent 会各自认领,并在 pipeline 节点上互相交接。
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import httpx

from ..config import get_settings

DEMO_TASKS = [
    {
        "title": "订单查询接口支持分页与排序",
        "description": "现在查询接口一次最多返回 100 条,数据量涨上来以后页面卡住。需要支持 page/size/sort,默认按创建时间倒序。",
        "required_capability": "analyze",
        "priority": 8,
    },
    {
        "title": "用户中心从单体里拆出来",
        "description": "用户相关逻辑已经占了单体的三分之一,需要独立服务,保留现有接口兼容。",
        "required_capability": "design",
        "priority": 9,
    },
    {
        "title": "支付回调补一套回归测试",
        "description": "上月两次回调重复入账,需要幂等 + 重复回调的回归用例。",
        "required_capability": "test",
        "priority": 9,
    },
    {
        "title": "季度技术架构评审材料",
        "description": "汇总本季度架构变更、线上事故与技术债,给出下一季度建议。",
        "required_capability": "review",
        "priority": 7,
    },
    {
        "title": "新同事上手指南",
        "description": "本地起服务、跑测试、提交规范、常见问题,写成一份文档。",
        "required_capability": "docs",
        "priority": 4,
    },
    {
        "title": "把客服工单系统的接入需求受理一下",
        "description": "工单要接第三方消息通道,先受理并拆出后续任务。",
        "required_capability": "intake",
        "priority": 6,
    },
]


async def seed(hub: str, token: str, count: int, extra: bool) -> None:
    headers = {"X-Operator-Token": token} if token else {}
    async with httpx.AsyncClient(base_url=hub, timeout=20.0) as client:
        r = await client.get("/api/health")
        if r.status_code != 200:
            print(f"✗ 连不上中心({r.status_code}),先启动 python -m agentmesh.hub")
            return
        created = 0
        for spec in DEMO_TASKS[:count]:
            resp = await client.post("/api/tasks", json=spec, headers=headers)
            if resp.status_code == 200:
                created += 1
                print(f"✓ {resp.json()['task_id']} · {spec['title']}  (需要 {spec['required_capability']})")
            else:
                print(f"✗ {spec['title']}:{resp.status_code} {resp.text[:120]}")
        if extra:
            resp = await client.post(
                "/api/tasks",
                json={
                    "title": "自选任务:随便提一条,看谁先认领",
                    "description": "任意能力都可以做;没人认领就说明没有对应能力的 Agent 在线。",
                    "required_capability": "",
                    "priority": 3,
                },
                headers=headers,
            )
            if resp.status_code == 200:
                created += 1
                print(f"✓ {resp.json()['task_id']} · 自选任务(任意能力)")
        print(f"\n共创建 {created} 条任务。看板:http://{hub.replace('http://','')}/")


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(
        prog="python -m agentmesh.tools.seed", description="向中心灌一批演示任务"
    )
    parser.add_argument("--hub", default=f"http://127.0.0.1:{settings.port}")
    parser.add_argument("--token", default="", help="X-Operator-Token(若中心设置了 MESH_ENROLLMENT_TOKEN)")
    parser.add_argument("-n", "--count", type=int, default=len(DEMO_TASKS), help="灌几条")
    parser.add_argument("--extra", action="store_true", help="额外加一条任意能力的任务")
    args = parser.parse_args(argv)
    asyncio.run(seed(args.hub, args.token, max(0, args.count), args.extra))
    return 0


if __name__ == "__main__":
    sys.exit(main())