"""Agent 运行时 —— 一个员工 = 一个独立进程。

它和中心之间只有四个动作:注册、心跳、领活、干活(含交接)。
没有任何"中心给我派单"的通道;任务是我自己开口要的。

三个刻意的设计:
  1. 租约而非长锁:崩溃不会永久卡住任务,租约到期自动回队列。
  2. 交接靠能力协商:我知道下一步需要什么能力,自己找拥有该能力的同伴;
     找不到就说明没人能做,任务留在队列里等,而不是硬塞给别人。
  3. 本地镜像 + 本地验签:中心对我说的每一件事我都先验再信。
     验不过 → 记异议、拒绝采信。中心不可信时系统仍然可审计。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Any

import httpx

from ..capabilities import OUTCOME_HANDOFF, Reporter, resolve
from ..config import get_settings
from ..events import (
    EV_AGENT_REGISTERED,
    EV_TASK_CLAIMED,
    EV_TASK_COMPLETED,
    EV_TASK_CREATED,
    EV_TASK_FAILED,
    EV_TASK_HANDED_OFF,
    EV_TASK_PROGRESS,
    signed_payload_bytes,
)
from ..mirror import Mirror
from ..signing import load_or_create_signer
from ..signing import canonical_json


class AgentError(Exception):
    pass


class Agent:
    def __init__(
        self,
        *,
        agent_id: str,
        display_name: str,
        role: str = "",
        capabilities: list[str] | None = None,
        hub_url: str = "http://127.0.0.1:8765",
        keys_dir: Path | None = None,
        data_dir: Path | None = None,
        enrollment_token: str = "",
        step_seconds: float = 3.0,
        idle_poll: float = 1.2,
        mirror_interval: float = 3.0,
        verbose: bool = True,
    ) -> None:
        settings = get_settings()
        self.agent_id = agent_id
        self.display_name = display_name
        self.role = role
        self.capabilities = [c.lower() for c in (capabilities or [])]
        self.hub_url = hub_url.rstrip("/")
        self.enrollment_token = enrollment_token
        self.step_seconds = step_seconds
        self.idle_poll = idle_poll
        self.mirror_interval = mirror_interval
        self.verbose = verbose

        keys_dir = Path(keys_dir or settings.keys_dir)
        data_dir = Path(data_dir or settings.data_dir)
        (keys_dir / "agents").mkdir(parents=True, exist_ok=True)
        self.signer = load_or_create_signer(keys_dir / "agents" / f"{agent_id}.pem")
        self.public_pem = self.signer.public_pem().decode()
        self.fingerprint = self.signer.public_identity()

        self.mirror = Mirror(data_dir / "agents" / f"{agent_id}" / "mirror.db", agent_id)
        self._registered = False
        self._current_task: dict[str, Any] | None = None
        self._last_mirror_report: dict[str, Any] = {}
        self._running = True
        self.http = httpx.AsyncClient(base_url=self.hub_url, timeout=15.0)

    # ---- 日志 ----
    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"[{time.strftime('%H:%M:%S')}] {self.agent_id:<14} {msg}", flush=True)

    # ---- 签名 ----
    def sign(self, type: str, task_id: str | None, payload: dict[str, Any]) -> str:
        """用本 Agent 的私钥为事件内容签名。签的是内容本身,不是旁支摘要。"""
        return self.signer.sign(
            signed_payload_bytes(f"agent:{self.agent_id}", type, task_id, payload)
        )

    async def _post(self, path: str, body: dict[str, Any]) -> httpx.Response:
        return await self.http.post(path, json=body)

    # ---- 注册 ----
    async def register(self) -> None:
        payload = {
            "op": "register",
            "agent_id": self.agent_id,
            "display_name": self.display_name,
            "capabilities": self.capabilities,
            "key_fingerprint": self.fingerprint,
        }
        sig = self.sign(EV_AGENT_REGISTERED, None, payload)
        headers = {"X-Enrollment-Token": self.enrollment_token} if self.enrollment_token else {}
        for attempt in range(1, 6):
            try:
                resp = await self.http.post(
                    "/api/agents/register",
                    json={
                        "agent_id": self.agent_id,
                        "display_name": self.display_name,
                        "role": self.role,
                        "capabilities": self.capabilities,
                        "pubkey_pem": self.public_pem,
                        "alg": self.signer.algorithm,
                        "meta": {"pid": None, "started_at": time.time()},
                        "payload": payload,
                        "attest_sig": sig,
                    },
                    headers=headers,
                )
                if resp.status_code == 200:
                    self._registered = True
                    self.log(f"已注册,公钥指纹 {self.fingerprint},能力 {self.capabilities}")
                    await self.refresh_keys()
                    return
                detail = resp.json().get("detail", resp.text)
                if resp.status_code in (403, 401):
                    raise AgentError(f"注册被拒(鉴权失败):{detail}")
                self.log(f"注册返回 {resp.status_code}:{detail},重试中")
            except AgentError:
                raise
            except httpx.HTTPError as exc:
                self.log(f"连不上中心({exc.__class__.__name__}),第 {attempt} 次重试")
            await asyncio.sleep(min(2 ** attempt * 0.4, 6))
        raise AgentError("多次重试后仍无法注册,请确认中心已启动")

    async def refresh_keys(self) -> None:
        """取回中心与同伴公钥 —— 没有公钥就无法验证,也就谈不上信任。"""
        try:
            resp = await self.http.get("/api/keys")
            if resp.status_code != 200:
                return
            keys: dict[str, str] = resp.json().get("keys", {})
            if "hub" in keys:
                self.mirror.set_hub_key(keys["hub"])
            # 自己的公钥也要存:Agent 必须能独立验证"这真是我干的吗",
            # 包括自己过去做过的事 —— 不然镜像里一半事件无法验签。
            for agent_id, pem in keys.items():
                if agent_id != "hub":
                    self.mirror.upsert_peer_key(agent_id, pem)
        except httpx.HTTPError as exc:
            self.log(f"取公钥失败:{exc}")

    # ---- 心跳 ----
    async def heartbeat_loop(self) -> None:
        settings = get_settings()
        while self._running:
            try:
                task = self._current_task
                resp = await self._post(
                    "/api/agents/heartbeat",
                    {
                        "agent_id": self.agent_id,
                        "current_task": task["task_id"] if task else None,
                        "status_detail": self._status_detail(),
                    },
                )
                if resp.status_code == 409:
                    self.log("租约已失效(可能心跳超时),放弃当前任务")
                    self._current_task = None
            except httpx.HTTPError:
                pass
            await asyncio.sleep(settings.heartbeat_seconds)

    def _status_detail(self) -> str:
        m = self._last_mirror_report or self.mirror.stats()
        disputed = m.get("rejected") or []
        flag = " ⚠异议" if disputed else ""
        return f"镜像 seq{m.get('mirrored_events', 0)}·本地验签通过{flag}"

    # ---- 镜像同步(先验后存) ----
    async def mirror_loop(self) -> None:
        while self._running:
            try:
                head = self.mirror.head_seq()
                resp = await self.http.get("/api/events", params={"after_seq": head, "limit": 300})
                if resp.status_code == 200:
                    events = resp.json().get("events", [])
                    if events:
                        report = self.mirror.sync(events)
                        self._last_mirror_report = {
                            "mirrored_events": self.mirror.stats()["mirrored_events"],
                            "accepted": report["accepted"],
                            "rejected": report["rejected"],
                        }
                        for bad in report["rejected"]:
                            # 中心给的东西验不过 —— 记下来、说出来,但不采信
                            self.log(
                                f"🚨 中心推来的事件本地验签失败(seq={bad['seq']}):{bad['reason'][:80]}"
                                " → 已拒绝并记入本地异议表"
                            )
                    else:
                        self._last_mirror_report = self.mirror.stats()
                await self.refresh_keys()
            except httpx.HTTPError:
                pass
            await asyncio.sleep(self.mirror_interval)

    # ---- 工作循环 ----
    async def work_loop(self) -> None:
        while self._running:
            if self._current_task is not None:
                await asyncio.sleep(0.2)
                continue
            try:
                task = await self.claim_next()
            except httpx.HTTPError as exc:
                self.log(f"认领请求失败:{exc}")
                await asyncio.sleep(2)
                continue
            if not task:
                await asyncio.sleep(self.idle_poll)
                continue
            await self.execute(task)

    async def claim_next(self) -> dict[str, Any] | None:
        payload = {"op": "claim_next", "agent_id": self.agent_id, "capabilities": self.capabilities}
        resp = await self._post(
            "/api/tasks/claim-next",
            {
                "agent_id": self.agent_id,
                "capabilities": self.capabilities,
                "payload": payload,
                "attest_sig": self.sign(EV_TASK_CLAIMED, None, payload),
            },
        )
        if resp.status_code != 200:
            self.log(f"claim-next 被拒 {resp.status_code}:{resp.text[:160]}")
            return None
        data = resp.json()
        if not data.get("claimed"):
            return None
        task = data["task"]
        self.log(f"领到任务 {task['task_id']} · {task['title']}(需要 {task['required_capability'] or '任意'})")
        return task

    # ---- 执行 ----
    async def execute(self, task: dict[str, Any]) -> None:
        self._current_task = task
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        handler = resolve(task.get("required_capability"))

        def report(message: str, pct: int) -> None:
            # 真实能力在这里就是慢操作(调模型、跑构建);演示时用节拍模拟,
            # 目的是让租约、进度、交接在看板上是真实时序而不是一瞬间跳完。
            time.sleep(max(0.2, self.step_seconds / 3))
            loop.call_soon_threadsafe(queue.put_nowait, (message, pct))

        try:
            outcome = await asyncio.to_thread(handler, self, task, Reporter(report, str(self.mirror.db_path)))
            # 把进度事件和最终动作一起发出去,保持顺序
            while not queue.empty():
                await self._push_progress(task["task_id"], *queue.get_nowait())
            if outcome.kind == OUTCOME_HANDOFF:
                await self._do_handoff(task, outcome)
            else:
                await self._do_complete(task, outcome)
        except Exception as exc:  # 干活失败不能拖死进程,也不能让任务永远挂着
            self.log(f"执行异常:{type(exc).__name__}:{exc}")
            await self._do_fail(task, f"{type(exc).__name__}: {exc}")
        finally:
            self._current_task = None

    async def _push_progress(self, task_id: str, message: str, pct: int) -> None:
        payload = {"op": "progress", "task_id": task_id, "message": message, "pct": pct}
        try:
            resp = await self._post(
                f"/api/tasks/{task_id}/progress",
                {
                    "agent_id": self.agent_id,
                    "task_id": task_id,
                    "message": message,
                    "pct": pct,
                    "payload": payload,
                    "attest_sig": self.sign(EV_TASK_PROGRESS, task_id, payload),
                },
            )
            if resp.status_code == 200:
                self.log(f"  · {message}({pct}%)")
        except httpx.HTTPError:
            pass

    async def _do_complete(self, task: dict, outcome) -> None:
        task_id = task["task_id"]
        result = (outcome.result or "") + (
            f"\n\n[处理者] {self.display_name}({self.agent_id})"
        )
        payload = {"op": "complete", "task_id": task_id, "summary": result[:200]}
        resp = await self._post(
            f"/api/tasks/{task_id}/complete",
            {
                "agent_id": self.agent_id,
                "task_id": task_id,
                "result": result,
                "artifacts": outcome.artifacts,
                "payload": payload,
                "attest_sig": self.sign(EV_TASK_COMPLETED, task_id, payload),
            },
        )
        if resp.status_code == 200:
            self.log(f"✅ 完成 {task_id}")
        else:
            self.log(f"完成上报失败 {resp.status_code}:{resp.text[:160]}")
        # 自己长出的新任务:签名后交给中心。中心只能验签,不能代签、不能改写。
        for spec in outcome.spawn or []:
            await self._spawn_task(spec)

    async def _spawn_task(self, spec: dict[str, Any]) -> None:
        title = spec["title"]
        payload = {
            "op": "spawn",
            "title": title,
            "required_capability": spec.get("required_capability", ""),
        }
        try:
            resp = await self._post(
                "/api/tasks",
                {
                    "title": title,
                    "description": spec.get("description", ""),
                    "required_capability": spec.get("required_capability", ""),
                    "priority": spec.get("priority", 5),
                    "context": spec.get("context", {}),
                    "agent_id": self.agent_id,
                    "payload": payload,
                    "attest_sig": self.sign(EV_TASK_CREATED, None, payload),
                },
            )
            if resp.status_code == 200:
                self.log(f"🌱 新长出任务 {resp.json()['task_id']} · {title}")
            else:
                self.log(f"新任务创建失败 {resp.status_code}:{resp.text[:140]}")
        except httpx.HTTPError as exc:
            self.log(f"新任务创建失败:{exc}")

    async def _do_fail(self, task: dict, error: str) -> None:
        task_id = task["task_id"]
        payload = {"op": "fail", "task_id": task_id, "error": error[:200]}
        try:
            await self._post(
                f"/api/tasks/{task_id}/fail",
                {
                    "agent_id": self.agent_id,
                    "task_id": task_id,
                    "error": error,
                    "requeue": True,
                    "payload": payload,
                    "attest_sig": self.sign(EV_TASK_FAILED, task_id, payload),
                },
            )
            self.log(f"⚠️ 标记失败并已重新入队:{error[:60]}")
        except httpx.HTTPError:
            pass  # 租约到期会自动回收,不必在这里兜底

    # ---- 交接 ----
    async def find_peer(self, capability: str) -> str | None:
        """按能力找同伴。中心不给推荐位,我自己看花名册挑。"""
        try:
            resp = await self.http.get("/api/state")
            if resp.status_code != 200:
                return None
            agents = resp.json().get("agents", [])
        except httpx.HTTPError:
            return None
        candidates = [
            a for a in agents
            if a["agent_id"] != self.agent_id
            and a["enabled"]
            and a["online"]
            and capability.lower() in [c.lower() for c in a["capabilities"]]
        ]
        if not candidates:
            return None
        # 选活最少的那个:不是负载均衡算法,只是别把活全压给一个人
        candidates.sort(key=lambda a: (a["tasks_done"], a["registered_at"]))
        return candidates[0]["agent_id"]

    async def _do_handoff(self, task: dict, outcome) -> None:
        task_id = task["task_id"]
        peer = await self.find_peer(outcome.next_capability)
        if not peer:
            self.log(f"🔁 需要 {outcome.next_capability} 但当前没有在线同伴,自行收尾")
            await self._do_complete(task, outcome)
            return
        context = {
            **(task.get("context") or {}),
            **outcome.context,
            "previous_agent": self.agent_id,
            "previous_output": (outcome.result or "")[-1500:],
        }
        payload = {
            "op": "handoff",
            "task_id": task_id,
            "from": self.agent_id,
            "to": peer,
            "next_capability": outcome.next_capability,
            "reason": outcome.reason,
            "note": outcome.note[:200],
            "context": context,
        }
        resp = await self._post(
            f"/api/tasks/{task_id}/handoff",
            {
                "agent_id": self.agent_id,
                "task_id": task_id,
                "to_agent": peer,
                "next_capability": outcome.next_capability,
                "reason": outcome.reason,
                "note": outcome.note,
                "context": context,
                "payload": payload,
                "attest_sig": self.sign(EV_TASK_HANDED_OFF, task_id, payload),
            },
        )
        if resp.status_code == 200:
            self.log(
                f"🤝 交接 {task_id} → {peer}({outcome.reason})"
                f";下一步需要能力:{outcome.next_capability or '不变'}"
            )
        else:
            self.log(f"交接被拒 {resp.status_code}:{resp.text[:160]}")
            await self._do_complete(task, outcome)

    # ---- 运行 ----
    async def run(self) -> None:
        await self.register()
        self.log(f"开始工作 | 能力={','.join(self.capabilities) or '无'}")
        tasks = [
            asyncio.create_task(self.heartbeat_loop()),
            asyncio.create_task(self.mirror_loop()),
            asyncio.create_task(self.work_loop()),
        ]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            for t in tasks:
                t.cancel()
            await self.http.aclose()

    def stop(self) -> None:
        self._running = False


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m agentmesh.agent",
        description="启动一个 Agent 进程(一个员工 = 一个进程)",
    )
    p.add_argument("--id", required=True, help="Agent 唯一 id,例如 arch-nova")
    p.add_argument("--name", default=None, help="显示名,默认与 id 相同")
    p.add_argument("--role", default="", help="岗位说明,例如 后端架构")
    p.add_argument(
        "--capabilities",
        default="",
        help="逗号分隔的能力,例如 analyze,design。需要与任务 required_capability 对上",
    )
    p.add_argument("--hub", default="http://127.0.0.1:8765", help="中心地址")
    p.add_argument("--token", default=None, help="注册口令(对应 MESH_ENROLLMENT_TOKEN)")
    p.add_argument("--step-seconds", type=float, default=3.0, help="每个能力步骤的模拟耗时")
    p.add_argument("--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    caps = [c.strip() for c in args.capabilities.split(",") if c.strip()]
    agent = Agent(
        agent_id=args.id,
        display_name=args.name or args.id,
        role=args.role,
        capabilities=caps,
        hub_url=args.hub,
        enrollment_token=args.token if args.token is not None else settings.enrollment_token,
        step_seconds=args.step_seconds,
        verbose=not args.quiet,
    )
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        agent.stop()
    except AgentError as exc:
        print(f"[{args.id}] 启动失败:{exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())