"""Hub(中心服务)。

它做的只有三件事:
  1. 保存不可篡改的事件日志(哈希链)
  2. 做原子认领与租约管理(不做"指派",谁都能来领)
  3. 提供看板与验证接口

它刻意不做的事:
  - 不决定谁该干什么(没有调度器,任务靠认领)
  - 不解释任务内容(不懂业务,只管状态流转)
  - 不持有任何 Agent 的私钥(所以它无法伪造 Agent 的行为)

一句话:中心是"公证人",不是"教练"。
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from ..auth import AuthError, check_operator_token, verify_agent_signature, verify_with_public_key
from ..config import get_settings
from ..events import (
    EV_AGENT_KEY_ROTATED,
    EV_AGENT_REGISTERED,
    EV_TASK_CLAIMED,
    EV_TASK_COMPLETED,
    EV_TASK_CREATED,
    EV_TASK_FAILED,
    EV_TASK_HANDED_OFF,
    EV_TASK_PROGRESS,
    EV_TASK_RELEASED,
    Event,
    verify_chain,
)
from ..protocol import (
    AgentToggleRequest,
    ClaimNextRequest,
    ClaimRequest,
    CompleteRequest,
    CreateTaskRequest,
    FailRequest,
    HeartbeatRequest,
    HandoffRequest,
    ProgressRequest,
    RegisterRequest,
    RotateKeyRequest,
)
from ..signing import fingerprint, load_or_create_signer, write_public_key
from ..store import STATE_CLAIMED, STATE_READY, ConflictError, NotFound, Store
from .broadcaster import Broadcaster

STATIC_DIR = Path(__file__).parent / "static"


class Mesh:
    """服务容器:持有 store、签名器、广播器。"""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.settings.ensure_dirs()
        # 中心的签名器:只对链的完整性负责(system/operator 事件),不碰 Agent 私钥
        self.hub_signer = load_or_create_signer(self.settings.hub_privkey)
        write_public_key(self.settings.hub_pubkey, "hub", self.hub_signer.public_pem())
        self.store = Store(self.settings.db_path, hub_signer=self.hub_signer)
        self.bus = Broadcaster()
        self.started_at = time.time()
        self._sweeper: asyncio.Task | None = None

    # ---- 验签用的公钥表 ----
    def current_key_for(self, actor: str) -> bytes | None:
        """鉴权用:只看当前公钥。换过钥的 Agent,旧钥不再有权产生新动作。"""
        pem = self.store.current_actor_keys().get(actor)
        return pem.encode() if pem else None

    def public_key_for(self, actor: str) -> list[bytes] | None:
        """返回该身份用过的全部公钥(当前 + 历史),验签时挨个试。

        只返回当前公钥会让"换过钥的 Agent 的历史事件"全部判为伪造,
        那等于把审计能力做成了摆设。
        """
        pems = self.store.known_actors().get(actor)
        return [p.encode() for p in pems] if pems else None

    # ---- 视图构造 ----
    def agent_views(self) -> list[dict[str, Any]]:
        now = time.time()
        rows = self.store.list_agents()
        busy: dict[str, dict[str, Any]] = {}
        for t in self.store.list_tasks(STATE_CLAIMED):
            if t["owner"]:
                busy[t["owner"]] = t
        out = []
        for r in rows:
            age = now - r["last_seen"]
            enabled = bool(r["enabled"])
            online = age <= self.settings.offline_after_seconds
            task = busy.get(r["agent_id"])
            if not enabled:
                status = "disabled"
            elif not online:
                status = "offline"
            elif task:
                status = "busy"
            else:
                status = "idle"
            out.append(
                {
                    "agent_id": r["agent_id"],
                    "display_name": r["display_name"],
                    "role": r["role"],
                    "capabilities": json.loads(r["capabilities"] or "[]"),
                    "enabled": enabled,
                    "online": online,
                    "status": status,
                    "current_task": task["task_id"] if task else None,
                    "current_task_title": task["title"] if task else None,
                    "registered_at": r["registered_at"],
                    "last_seen": r["last_seen"],
                    "heartbeat_age": round(age, 1),
                    "key_fingerprint": r["key_fingerprint"],
                    "tasks_done": r["tasks_done"],
                    "handoffs_given": r["handoffs_given"],
                    "handoffs_recv": r["handoffs_recv"],
                    "lease_remaining": (
                        round(task["lease_expires_at"] - now, 1) if task else None
                    ),
                }
            )
        return out

    def task_views(self) -> list[dict[str, Any]]:
        now = time.time()
        out = []
        for t in self.store.list_tasks():
            lease_remaining = None
            if t["state"] == STATE_CLAIMED and t["lease_expires_at"]:
                lease_remaining = round(t["lease_expires_at"] - now, 1)
            handoff_open = bool(
                t["preferred_agent"] and (t["preferred_until"] or 0) > now
            )
            out.append(
                {
                    **{k: v for k, v in t.items() if not k.startswith("_")},
                    "context": json.loads(t["context"] or "{}"),
                    "lease_remaining": lease_remaining,
                    "handoff_open": handoff_open,
                    "age": round(now - t["created_at"], 1),
                }
            )
        return out

    def snapshot(self) -> dict[str, Any]:
        head_seq, head_hash = self.store.head()
        return {
            "head_seq": head_seq,
            "head_hash": head_hash,
            "hub_alg": self.hub_signer.algorithm,
            "hub_fingerprint": self.hub_signer.public_identity(),
            "started_at": self.started_at,
            "stats": self.store.stats(),
            "agents": self.agent_views(),
            "tasks": self.task_views(),
            "ws_clients": self.bus.client_count,
        }

    # ---- 事件广播 ----
    async def publish(self, *events: Event) -> None:
        for ev in events:
            await self.bus.broadcast({"type": "event", "event": ev.to_dict()})


def create_app() -> FastAPI:
    settings = get_settings()
    mesh = Mesh()

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        # 租约清扫:Agent 崩了任务自动回队列,这是"没有中心也会自愈"的关键
        async def sweeper() -> None:
            while True:
                try:
                    released = await asyncio.to_thread(mesh.store.release_expired_leases)
                    for task_id, prev_owner in released:
                        await mesh.bus.broadcast(
                            {
                                "type": "notice",
                                "level": "warn",
                                "text": f"任务 {task_id} 的租约到期,已从 {prev_owner} 回收并重新入队",
                                "task_id": task_id,
                            }
                        )
                    await mesh.bus.broadcast({"type": "tick", "stats": mesh.store.stats()})
                except Exception as exc:  # 清扫失败不能拖垮整个服务
                    print(f"[hub] lease sweeper error: {exc}")
                await asyncio.sleep(2)

        mesh._sweeper = asyncio.create_task(sweeper())
        print(f"[hub] AgentMesh 中心已启动  data={settings.data_dir}  db={settings.db_path}")
        print(f"[hub] 中心公钥指纹 {mesh.hub_signer.public_identity()}  alg={mesh.hub_signer.algorithm}")
        try:
            yield
        finally:
            mesh._sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await mesh._sweeper

    app = FastAPI(
        title="AgentMesh Hub",
        version="1.0.0",
        description=(
            "去中心化多智能体任务交接系统的中心服务。\n\n"
            "**中心不做任务指派** —— 任务靠 Agent 主动认领(claim),中心只做原子裁决和审计。\n"
            "**每条事件都进哈希链,并带行为者的 Ed25519 签名** —— "
            "任何人拿 `/api/export` 和 `/api/keys/` 就能离线独立验证。"
        ),
        lifespan=lifespan,
    )
    app.state.mesh = mesh
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def _fail(exc: Exception) -> HTTPException:
        return HTTPException(status_code=getattr(exc, "status", 409), detail=str(exc))

    def _operator(header: str | None) -> None:
        with contextlib.suppress(AuthError):
            check_operator_token(header, settings.enrollment_token)
            return
        raise HTTPException(status_code=401, detail="X-Operator-Token 不正确或缺失")

    def _auth(actor: str, type: str, task_id: str | None, payload: dict, sig: str) -> None:
        try:
            verify_agent_signature(
                mesh.current_key_for, actor=actor, type=type,
                task_id=task_id, payload=payload, attest_sig=sig,
            )
        except AuthError as exc:
            raise HTTPException(status_code=exc.status, detail=exc.message)

    # ================= Agent 侧接口 =================

    @app.post("/api/agents/register", tags=["agent"], summary="Agent 注册/重连(需内容签名)")
    async def register(req: RegisterRequest, x_enrollment_token: str | None = Header(None)):
        if settings.enrollment_token:
            check_operator_token(x_enrollment_token, settings.enrollment_token)
        actor = f"agent:{req.agent_id}"
        pem_text = req.pubkey_pem
        try:
            from ..signing import Ed25519Signer

            # 校验提交的确实是可用的公钥,并取其指纹(不做任何"生成密钥"的事)
            fp = Ed25519Signer.from_public_pem(pem_text.encode())
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"公钥解析失败:{exc}")

        payload = dict(req.payload)
        payload["key_fingerprint"] = fp
        # 注册是"提交公钥"这一步,验签只能拿这份公钥自己验 —— 它证明的是
        # "后面所有用这把钥匙签的事件都出自同一个持有者"。
        # 谁有资格加入,由 enrollment token 把关;一旦登记,公钥即被钉死,
        # 之后同名不同钥的请求会被 store 拒绝。
        try:
            verify_with_public_key(
                pem_text, actor=actor, type=EV_AGENT_REGISTERED,
                task_id=None, payload=payload, attest_sig=req.attest_sig,
            )
        except AuthError as exc:
            raise HTTPException(status_code=exc.status, detail=exc.message)

        try:
            agent, ev = await asyncio.to_thread(
                mesh.store.register_agent,
                agent_id=req.agent_id,
                display_name=req.display_name,
                role=req.role,
                capabilities=req.capabilities,
                pubkey_pem=pem_text,
                key_fingerprint=fp,
                alg=req.alg,
                payload=payload,
                attest_sig=req.attest_sig,
                meta=req.meta,
            )
        except (ConflictError, NotFound) as exc:
            raise _fail(exc)
        write_public_key(settings.hub_pubkey, req.agent_id, pem_text.encode())
        await mesh.publish(ev)
        return {"ok": True, "seq": ev.seq, "event_id": ev.event_id, "hash": ev.hash,
                "agent": agent["agent_id"], "key_fingerprint": fp}

    @app.post("/api/agents/heartbeat", tags=["agent"], summary="心跳(不写链,只刷新在线状态)")
    async def heartbeat(req: HeartbeatRequest):
        agent = mesh.store.get_agent(req.agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent 未注册")
        await asyncio.to_thread(mesh.store.touch_agent, req.agent_id)
        task = None
        if req.current_task:
            t = mesh.store.get_task(req.current_task)
            if t and t["owner"] == req.agent_id and t["state"] == STATE_CLAIMED:
                task = t
        if task:
            await asyncio.to_thread(
                mesh.store.renew_lease, req.current_task, req.agent_id, settings.lease_seconds
            )
        return {"ok": True, "lease_seconds": settings.lease_seconds}

    @app.post("/api/tasks/claim-next", tags=["agent"], summary="认领下一个我能做的任务")
    async def claim_next(req: ClaimNextRequest):
        actor = f"agent:{req.agent_id}"
        _auth(actor, EV_TASK_CLAIMED, None, req.payload, req.attest_sig)
        lease = req.lease_seconds or settings.lease_seconds
        # payload 必须与 Agent 签名的逐字节一致,所以这里原样透传,不由服务端组装
        task = await asyncio.to_thread(
            mesh.store.claim_next,
            req.agent_id,
            req.capabilities,
            lease,
            handoff_priority_seconds=settings.handoff_priority_seconds,
            payload_factory=lambda _task_id, _row: req.payload,
            attest_sig=req.attest_sig,
        )
        if not task:
            return {"ok": True, "claimed": False, "reason": "queue_empty"}
        ev = task.get("_last_event")
        if ev:
            await mesh.publish(ev)
        payload = {k: v for k, v in task.items() if not k.startswith("_")}
        payload["context"] = json.loads(payload.get("context") or "{}")
        payload["lease_remaining"] = lease
        return {"ok": True, "claimed": True, "task": payload}

    @app.post("/api/tasks/claim", tags=["agent"], summary="认领指定任务")
    async def claim(req: ClaimRequest):
        actor = f"agent:{req.agent_id}"
        _auth(actor, EV_TASK_CLAIMED, req.task_id, req.payload, req.attest_sig)
        task, reason = await asyncio.to_thread(
            mesh.store.claim_task, req.task_id, req.agent_id, settings.lease_seconds,
            payload=req.payload, attest_sig=req.attest_sig,
        )
        if not task:
            status = {"not_found": 404, "already_claimed": 409, "conflict": 409}.get(reason, 409)
            raise HTTPException(
                status_code=status,
                detail={"already_claimed": "任务已被别人领了", "not_found": "任务不存在",
                        "conflict": "交接优先窗口内,任务正等着指定 Agent 来领"}.get(reason, reason),
            )
        ev = task.get("_last_event")
        if ev:
            await mesh.publish(ev)
        payload = {k: v for k, v in task.items() if not k.startswith("_")}
        payload["context"] = json.loads(payload.get("context") or "{}")
        return {"ok": True, "task": payload}

    @app.post("/api/tasks/{task_id}/progress", tags=["agent"], summary="上报进度")
    async def progress(task_id: str, req: ProgressRequest):
        actor = f"agent:{req.agent_id}"
        _auth(actor, EV_TASK_PROGRESS, task_id, req.payload, req.attest_sig)
        try:
            _, ev = await asyncio.to_thread(
                mesh.store.record_progress, task_id, req.agent_id,
                payload=req.payload, attest_sig=req.attest_sig,
            )
        except ConflictError as exc:
            raise _fail(exc)
        await mesh.publish(ev)
        return {"ok": True, "seq": ev.seq, "hash": ev.hash}

    @app.post("/api/tasks/{task_id}/handoff", tags=["agent"], summary="把任务交接给同伴")
    async def handoff(task_id: str, req: HandoffRequest):
        actor = f"agent:{req.agent_id}"
        _auth(actor, EV_TASK_HANDED_OFF, task_id, req.payload, req.attest_sig)
        try:
            _, ev = await asyncio.to_thread(
                mesh.store.handoff_task,
                task_id=task_id,
                from_agent=req.agent_id,
                to_agent=req.to_agent,
                next_capability=req.next_capability,
                reason=req.reason,
                note=req.note,
                context=req.context,
                payload=req.payload,
                attest_sig=req.attest_sig,
                handoff_priority_seconds=settings.handoff_priority_seconds,
            )
        except (ConflictError, NotFound) as exc:
            raise _fail(exc)
        await mesh.publish(ev)
        return {
            "ok": True, "seq": ev.seq, "hash": ev.hash,
            "note": f"已交接给 {req.to_agent};对方有 {settings.handoff_priority_seconds}s 优先领取窗口,"
                    f"窗口过后其他人也可以领",
        }

    @app.post("/api/tasks/{task_id}/complete", tags=["agent"], summary="完成任务")
    async def complete(task_id: str, req: CompleteRequest):
        actor = f"agent:{req.agent_id}"
        _auth(actor, EV_TASK_COMPLETED, task_id, req.payload, req.attest_sig)
        try:
            _, ev = await asyncio.to_thread(
                mesh.store.complete_task, task_id, req.agent_id, req.result, req.artifacts,
                payload=req.payload, attest_sig=req.attest_sig,
            )
        except ConflictError as exc:
            raise _fail(exc)
        await mesh.publish(ev)
        return {"ok": True, "seq": ev.seq, "hash": ev.hash}

    @app.post("/api/tasks/{task_id}/fail", tags=["agent"], summary="标记失败(requeue 决定是否回队列)")
    async def fail(task_id: str, req: FailRequest):
        actor = f"agent:{req.agent_id}"
        _auth(actor, EV_TASK_FAILED, task_id, req.payload, req.attest_sig)
        try:
            _, ev = await asyncio.to_thread(
                mesh.store.fail_task, task_id, req.agent_id, req.error,
                requeue=req.requeue, payload=req.payload, attest_sig=req.attest_sig,
            )
        except ConflictError as exc:
            raise _fail(exc)
        await mesh.publish(ev)
        return {"ok": True, "seq": ev.seq, "requeued": req.requeue}

    @app.post("/api/agents/{agent_id}/rotate-key", tags=["agent"], summary="轮换公钥(旧钥无法再冒名)")
    async def rotate_key(agent_id: str, req: RotateKeyRequest):
        actor = f"agent:{agent_id}"
        try:
            from ..signing import Ed25519Signer

            fp = Ed25519Signer.from_public_pem(req.pubkey_pem.encode())
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"新公钥解析失败:{exc}")
        old = mesh.store.get_agent(agent_id)
        if old:
            # 轮换时用"新钥"验签证明不了持有旧钥,所以用旧公钥验这段内容
            verify_with_public_key(
                old["pubkey_pem"], actor=actor, type=EV_AGENT_KEY_ROTATED,
                task_id=None, payload=req.payload, attest_sig=req.attest_sig,
            )
        else:
            raise HTTPException(status_code=404, detail="Agent 不存在")
        ev = await asyncio.to_thread(
            mesh.store.rotate_agent_key, agent_id=agent_id, pubkey_pem=req.pubkey_pem,
            fingerprint=fp, alg=req.alg, payload=req.payload, attest_sig=req.attest_sig,
        )
        write_public_key(settings.hub_pubkey, agent_id, req.pubkey_pem.encode())
        await mesh.publish(ev)
        return {"ok": True, "seq": ev.seq, "key_fingerprint": fp}

    # ================= 管理端接口 =================

    @app.post("/api/tasks", tags=["admin"], summary="创建任务(管理端 token,或 Agent 自签新任务)")
    async def create_task(
        req: CreateTaskRequest, x_operator_token: str | None = Header(None)
    ):
        # 两条来路:管理端创建,或 Agent 自己长出新任务。后者必须自签。
        if req.agent_id:
            actor = f"agent:{req.agent_id}"
            if not req.payload or not req.attest_sig:
                raise HTTPException(
                    status_code=403, detail="Agent 创建任务必须带 payload 与 attest_sig"
                )
            if req.payload.get("title") != req.title:
                raise HTTPException(
                    status_code=409,
                    detail="签名内容里的 title 与请求不一致,拒收(签名必须与行为对应)",
                )
            _auth(actor, EV_TASK_CREATED, None, req.payload, req.attest_sig)
            created_by = actor
        else:
            _operator(x_operator_token)
            created_by = "operator"

        task, ev = await asyncio.to_thread(
            mesh.store.create_task,
            title=req.title, description=req.description,
            required_capability=req.required_capability, priority=req.priority,
            context=req.context, created_by=created_by,
            due_at=req.due_at,
            payload=req.payload,
            attest_sig=req.attest_sig,
        )
        await mesh.publish(ev)
        return {"ok": True, "task_id": task["task_id"], "seq": ev.seq, "created_by": created_by}

    @app.post("/api/tasks/{task_id}/cancel", tags=["admin"], summary="取消任务")
    async def cancel(task_id: str, x_operator_token: str | None = Header(None)):
        _operator(x_operator_token)
        try:
            _, ev = await asyncio.to_thread(mesh.store.cancel_task, task_id)
        except NotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        await mesh.publish(ev)
        return {"ok": True, "seq": ev.seq}

    @app.post("/api/agents/{agent_id}/enabled", tags=["admin"], summary="启用/禁用某个 Agent")
    async def set_enabled(
        agent_id: str, req: AgentToggleRequest, x_operator_token: str | None = Header(None)
    ):
        _operator(x_operator_token)
        try:
            ev = await asyncio.to_thread(mesh.store.set_agent_enabled, agent_id, req.enabled)
        except NotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        await mesh.publish(ev)
        return {"ok": True, "enabled": req.enabled}

    # ================= 读取与验证 =================

    @app.get("/api/health", tags=["read"], summary="健康检查")
    async def health():
        return {
            "ok": True,
            "version": app.version,
            "uptime": round(time.time() - mesh.started_at, 1),
            "events": mesh.store.count_events(),
            "ws_clients": mesh.bus.client_count,
        }

    @app.get("/api/state", tags=["read"], summary="看板全量快照")
    async def state():
        return mesh.snapshot()

    @app.get("/api/events", tags=["read"], summary="拉取事件(增量)")
    async def events(
        after_seq: int = Query(-1, ge=-1),
        limit: int = Query(200, ge=1, le=2000),
        task_id: str | None = None,
    ):
        evs = await asyncio.to_thread(
            mesh.store.get_events, after_seq=after_seq, limit=limit, task_id=task_id
        )
        return {"events": [e.to_dict() for e in evs], "head": mesh.store.head()[0]}

    @app.get("/api/tasks/{task_id}/timeline", tags=["read"], summary="单个任务的完整交接链")
    async def timeline(task_id: str):
        evs = await asyncio.to_thread(mesh.store.get_events, after_seq=-1, limit=1000, task_id=task_id)
        task = mesh.store.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")
        return {
            "task": {**{k: v for k, v in task.items() if not k.startswith("_")},
                     "context": json.loads(task["context"] or "{}")},
            "events": [e.to_dict() for e in evs],
        }

    @app.get("/api/verify", tags=["verify"], summary="校验哈希链 + 所有事件签名")
    async def verify(
        after_seq: int = Query(-1, ge=-1),
        limit: int = Query(100000, ge=1, le=1000000),
    ):
        """独立重算 hash 与签名。不依赖中心自称"我是清白的"。"""
        evs = await asyncio.to_thread(mesh.store.get_events, after_seq=after_seq, limit=limit)
        report = verify_chain(
            evs, mesh.public_key_for,
            expected_prev_hash=evs[0].prev_hash if (after_seq >= 0 and evs) else "0" * 64,
            check_link=True,
            hub_public_pem=mesh.hub_signer.public_pem(),
        )
        report.ranges.append(f"hub head = seq {mesh.store.head()[0]} / {mesh.store.head()[1][:12]}")
        return report.to_dict()

    @app.get("/api/export", tags=["verify"], summary="导出完整事件日志(供离线校验)")
    async def export():
        evs = await asyncio.to_thread(mesh.store.get_events, after_seq=-1, limit=1_000_000)
        return {
            "exported_at": time.time(),
            "head_seq": evs[-1].seq if evs else -1,
            "head_hash": evs[-1].hash if evs else "0" * 64,
            "events": [e.to_dict() for e in evs],
        }

    @app.get("/api/keys", tags=["verify"], summary="公钥目录(可公开)")
    async def keys():
        keys = {}
        for p in sorted(settings.hub_pubkey.glob("*.pem")):
            keys[p.stem] = p.read_text()
        return {"keys": keys, "fingerprints": {k: fingerprint(v) for k, v in keys.items()}}

    @app.get("/api/keys/{actor}.pem", tags=["verify"], include_in_schema=False)
    async def key_file(actor: str):
        p = settings.hub_pubkey / f"{actor}.pem"
        if not p.exists():
            raise HTTPException(status_code=404, detail="公钥不存在")
        return Response(p.read_bytes(), media_type="application/x-pem-file")

    # ================= WebSocket =================

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        q = await mesh.bus.connect(ws)
        await q.put(json.dumps({"type": "hello", "head_seq": mesh.store.head()[0]}, ensure_ascii=False))
        try:
            while True:
                raw = await ws.receive_text()
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if msg.get("type") == "sync":
                    after = int(msg.get("after_seq", -1))
                    evs = await asyncio.to_thread(mesh.store.get_events, after_seq=after, limit=500)
                    await q.put(
                        json.dumps(
                            {"type": "sync_done",
                             "events": [e.to_dict() for e in evs],
                             "head_seq": mesh.store.head()[0]},
                            ensure_ascii=False, default=str,
                        )
                    )
                elif msg.get("type") == "ping":
                    await q.put(json.dumps({"type": "pong", "ts": time.time()}))
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            mesh.bus.disconnect(ws)

    # ================= 静态看板 =================
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        async def index():
            return FileResponse(STATIC_DIR / "index.html")

        @app.get("/favicon.ico", include_in_schema=False)
        async def favicon():
            icon = STATIC_DIR / "favicon.svg"
            return FileResponse(icon, media_type="image/svg+xml") if icon.exists() else Response(status_code=204)

    @app.exception_handler(AuthError)
    async def auth_handler(request: Request, exc: AuthError):
        return JSONResponse(status_code=exc.status, content={"detail": exc.message})

    return app


app = create_app()

# 注意:这里刻意不写 `app = create_app()`。
# 模块级建应用会导致"只要 import 这个模块就建库建目录",测试里换个数据目录也不生效 ——
# 踩过一次。需要 uvicorn 直接加载时用 agentmesh.hub.__main__ 即可。
