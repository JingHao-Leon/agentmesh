"""事件与哈希链。

中心(HUB)拿不到 Agent 的私钥 —— 这是故意的,否则去中心化只是说法。
所以事件有三块内容,分工必须清楚:

    payload   内容本体。谁做的这件事、内容是什么。由行为者签名。
    server    中心补充的事实(租约到期时间、重试次数、解析出的任务 id 等)。
              中心可以填,但它改不了 payload。
    prev_hash / hash / sig   链结构。由中心签名。

两层完整性,缺一不可:

  第一层 哈希链
      hash = sha256(canonical({prev_hash, seq, ts, type, actor, task_id,
                               payload, server, attest_sig, attest_task_id, alg}))
      每个 hash 咬住前一个。任何字段被改一个字节、从中间删一条、插一条,
      后面全部对不上。回答的是:"历史上有没有被动手脚?"

  第二层 归属签名
      attest_sig = agent 私钥对 canonical({actor, type, task_id, payload}) 的签名
      payload 就是 Agent 自己提交的那份内容,中心一个字节都改不了 ——
      想改就得连签名一起伪造,而中心没有 Agent 私钥。
      回答的是:"这事到底是谁干的、内容是不是他说的?"

⚠ 设计要点:签名必须直接覆盖"用户可见的内容",不能只签一个旁支字段。
早期版本让 Agent 签 intent、把正文放在未签名的 payload 里,结果中心可以
改 payload 再用中心私钥把整条链重算重签,校验器完全看不出来 ——
`tools/tamper.py` 的攻击 B 就是复现这个漏洞的。现在 payload 本身被签。

任何第三方拿 SQLite 文件 + 公钥目录即可离线校验,不需要信任中心,也不需要联网。
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable

from . import GENESIS_HASH, __version__
from .signing import canonical_json, verify_signature

# ---- 事件类型 -------------------------------------------------------------
# actor: "agent:<id>" | "operator"(人工/系统创建任务) | "system"(租约回收等自动行为)
EV_MESH_STARTED = "mesh.started"
EV_AGENT_REGISTERED = "agent.registered"
EV_AGENT_KEY_ROTATED = "agent.key_rotated"
EV_AGENT_ENABLED = "agent.enabled"
EV_AGENT_DISABLED = "agent.disabled"
EV_TASK_CREATED = "task.created"
EV_TASK_CLAIMED = "task.claimed"
EV_TASK_PROGRESS = "task.progress"
EV_TASK_HANDED_OFF = "task.handed_off"
EV_TASK_RELEASED = "task.released"
EV_TASK_COMPLETED = "task.completed"
EV_TASK_FAILED = "task.failed"

ALL_EVENT_TYPES = (
    EV_MESH_STARTED, EV_AGENT_REGISTERED, EV_AGENT_KEY_ROTATED, EV_AGENT_ENABLED,
    EV_AGENT_DISABLED, EV_TASK_CREATED, EV_TASK_CLAIMED, EV_TASK_PROGRESS,
    EV_TASK_HANDED_OFF, EV_TASK_RELEASED, EV_TASK_COMPLETED, EV_TASK_FAILED,
)

# 仅用于文档展示:哪些事件的 actor 应该是 Agent。
# 真正的校验规则不靠这张表 —— 只要 actor 以 agent: 开头,就必须有归属签名。
# 按类型白名单判定会留下口子:将来新增一个事件类型忘了加白名单,就等于免签。
AGENT_OWNED_TYPES = frozenset(
    {EV_AGENT_REGISTERED, EV_AGENT_KEY_ROTATED, EV_TASK_CLAIMED, EV_TASK_PROGRESS,
     EV_TASK_HANDED_OFF, EV_TASK_COMPLETED, EV_TASK_FAILED, EV_TASK_CREATED}
)


def signed_payload_bytes(
    actor: str, type: str, task_id: str | None, payload: dict[str, Any]
) -> bytes:
    """Agent 签名的确定性字节表示。Agent 与中心必须用同一个函数。"""
    return canonical_json({"actor": actor, "type": type, "task_id": task_id, "payload": payload})


@dataclass
class Event:
    seq: int
    event_id: str
    ts: float
    type: str
    actor: str
    task_id: str | None
    payload: dict[str, Any]          # 行为者签署的内容
    server: dict[str, Any]           # 中心补充的事实(未签名,但在哈希内)
    attest_sig: str | None
    # Agent 签名时使用的 task_id。与 task_id 分开记录,因为有一种情况二者必然不同:
    # claim-next 里任务由中心在认领时才确定,Agent 签名时还不知道是哪条,签的是 None。
    # 事后复验必须用签名当时的值,否则一条诚实的认领会被误判成伪造。
    attest_task_id: str | None
    alg: str
    prev_hash: str
    hash: str
    sig: str

    # ---- 哈希层 ----
    def hashed_body(self) -> dict[str, Any]:
        """参与 hash 的全部字段。刻意不含 hash 自身。"""
        return {
            "seq": self.seq,
            "event_id": self.event_id,
            "ts": self.ts,
            "type": self.type,
            "actor": self.actor,
            "task_id": self.task_id,
            "payload": self.payload,
            "server": self.server,
            "attest_sig": self.attest_sig,
            "attest_task_id": self.attest_task_id,
            "alg": self.alg,
        }

    def hash_bytes(self) -> bytes:
        return canonical_json({"prev_hash": self.prev_hash, **self.hashed_body()})

    def signed_bytes(self) -> bytes:
        return signed_payload_bytes(self.actor, self.type, self.attest_task_id, self.payload)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "Event":
        import json

        def _load(v, default):
            if v is None or v == "":
                return default
            return json.loads(v) if isinstance(v, str) else v

        return cls(
            seq=int(row["seq"]),
            event_id=row["event_id"],
            ts=float(row["ts"]),
            type=row["type"],
            actor=row["actor"],
            task_id=row["task_id"],
            payload=_load(row["payload"], {}),
            server=_load(row["server"], {}),
            attest_sig=row.get("attest_sig") or None,
            attest_task_id=row.get("attest_task_id"),
            alg=row["alg"],
            prev_hash=row["prev_hash"],
            hash=row["hash"],
            sig=row["sig"],
        )

    def short(self) -> str:
        return self.hash[:12]

    def summary(self) -> str:
        """看板/日志用的一行摘要。优先取 payload,回退到 server。"""
        p = self.payload or self.server or {}
        for key in ("summary", "message", "reason", "title", "note"):
            if p.get(key):
                return str(p[key])[:80]
        return ""


def compute_hash(prev_hash: str, body: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json({"prev_hash": prev_hash, **body})).hexdigest()


def build_event(
    *,
    seq: int,
    type: str,
    actor: str,
    hub_signer,
    prev_hash: str,
    task_id: str | None = None,
    payload: dict[str, Any] | None = None,
    server: dict[str, Any] | None = None,
    attest_sig: str | None = None,
    attest_task_id: str | None = "",  # "" = 与 task_id 相同;claim-next / 自建任务传 None
    ts: float | None = None,
    event_id: str | None = None,
) -> Event:
    """组装一条事件。

    hub_signer 中心签名器,负责链结构。
    payload    行为者内容,若行为者是 Agent 则由其私钥签署。
    server     中心补充的事实。绝不能把"用户可见的内容"放这里 —— 放了就没法验。
    """
    body = {
        "seq": seq,
        "event_id": event_id or uuid.uuid4().hex,
        "ts": time.time() if ts is None else ts,
        "type": type,
        "actor": actor,
        "task_id": task_id,
        "payload": payload or {},
        "server": server or {},
        "attest_sig": attest_sig,
        "attest_task_id": task_id if attest_task_id == "" else attest_task_id,
        "alg": hub_signer.algorithm,
    }
    h = compute_hash(prev_hash, body)
    sig = hub_signer.sign(canonical_json({"prev_hash": prev_hash, **body}))
    return Event(hash=h, sig=sig, prev_hash=prev_hash, **body)


def genesis_event(hub_signer, ts: float | None = None) -> Event:
    return build_event(
        seq=0,
        type=EV_MESH_STARTED,
        actor="system",
        hub_signer=hub_signer,
        prev_hash=GENESIS_HASH,
        payload={"version": __version__, "protocol": "agentmesh/1"},
        server={"hub_alg": hub_signer.algorithm},
        ts=ts,
        event_id="genesis",
    )


# ---- 校验 -----------------------------------------------------------------

def verify_hash(event: Event) -> tuple[bool, str]:
    expected = compute_hash(event.prev_hash, event.hashed_body())
    if expected != event.hash:
        return False, f"hash 不符:重算 {expected[:12]} ≠ 存储 {event.hash[:12]}"
    return True, "ok"


def verify_attest(event: Event, actor_public_pem: bytes) -> tuple[bool, str]:
    """第二层:Agent 是否真的为这份内容签过名。

    判定只看 actor:凡是 agent: 开头的,必须有归属签名。
    不看事件类型 —— 按类型维护白名单必然漏:新增一个事件类型忘了加进去,
    就等于悄悄免了签。operator / system 的事件不要求签名,它们本来就没有私钥。
    """
    if not event.actor.startswith("agent:"):
        return True, "ok"
    if not event.attest_sig:
        return False, f"{event.type} 的行为者是 Agent({event.actor}),却没有归属签名"
    ok, reason = verify_signature("ed25519", actor_public_pem, event.signed_bytes(), event.attest_sig)
    if not ok:
        return False, f"内容签名无效:{reason}(内容被改过,或并非 {event.actor} 所写)"
    return True, "ok"


def try_verify_attest(event: Event, candidate_pems: list[bytes]) -> tuple[bool, str]:
    """按候选密钥列表逐个试。

    为什么需要"列表":Agent 可以轮换密钥。轮换之后,换钥之前那些事件是旧私钥签的,
    只拿当前公钥去验,历史会被全部判为伪造 —— 那等于在最需要审计的时候把审计能力
    变成一堆假警报。正确做法是把密钥历史留着,验签时挨个试;
    同一份签名只可能对其中一把成立,所以多试几把不引入任何安全风险。
    """
    if not event.actor.startswith("agent:"):
        return True, "ok"
    if not event.attest_sig:
        return False, f"{event.type} 的行为者是 Agent({event.actor}),却没有归属签名"
    reason = "所有已知密钥都不匹配"
    for pem in candidate_pems:
        ok, why = verify_signature("ed25519", pem, event.signed_bytes(), event.attest_sig)
        if ok:
            return True, "ok"
        reason = why
    return False, f"内容签名无效:{reason}(内容被改过,或并非 {event.actor} 所写)"


def verify_event(
    event: Event, actor_public_pem: bytes, hub_public_pem: bytes | None = None
) -> tuple[bool, str]:
    """校验单条事件。

    actor_public_pem 该行为者的公钥(校验内容签名)
    hub_public_pem  中心公钥(可选)。Agent 本地镜像没有中心公钥时可跳过 ——
                    跳过的含义是"无法确认是中心签的",不是"确认没问题"。
    """
    ok, reason = verify_hash(event)
    if not ok:
        return False, reason
    pems = actor_public_pem if isinstance(actor_public_pem, list) else [actor_public_pem]
    ok, reason = try_verify_attest(event, pems)
    if not ok:
        return False, reason
    if hub_public_pem is not None:
        ok, reason = verify_signature("ed25519", hub_public_pem, event.hash_bytes(), event.sig)
        if not ok:
            return False, f"中心签名无效:{reason}"
    return True, "ok"


@dataclass
class ChainReport:
    total: int = 0
    verified: int = 0
    ok: bool = True
    head_hash: str = GENESIS_HASH
    head_seq: int = -1
    problems: list[dict[str, Any]] = field(default_factory=list)
    ranges: list[str] = field(default_factory=list)
    broken_at_seq: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "total": self.total,
            "verified": self.verified,
            "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "problems": self.problems,
            "ranges": self.ranges,
            "broken_at_seq": self.broken_at_seq,
        }


def verify_chain(
    events: Iterable[Event],
    public_key_for: Callable[[str], bytes | None],
    *,
    expected_prev_hash: str = GENESIS_HASH,
    check_link: bool = True,
    hub_public_pem: bytes | None = None,
) -> ChainReport:
    """验证事件序列:链接关系 + 每条事件的 hash + 内容归属签名 + (可选)中心签名。"""
    report = ChainReport(head_hash=expected_prev_hash)
    prev = expected_prev_hash
    first_seq: int | None = None

    for ev in events:
        report.total += 1
        report.head_seq = ev.seq
        report.head_hash = ev.hash
        if first_seq is None:
            first_seq = ev.seq

        if check_link and ev.prev_hash != prev:
            report.ok = False
            report.broken_at_seq = ev.seq
            report.problems.append(
                {
                    "seq": ev.seq,
                    "event_id": ev.event_id,
                    "kind": "broken_link",
                    "detail": (
                        f"prev_hash={ev.prev_hash[:12]} ≠ 前一条 hash={prev[:12]};"
                        "说明有事件被删除、插入或重排"
                    ),
                }
            )

        pem = public_key_for(ev.actor)
        if pem is None:
            report.ok = False
            report.problems.append(
                {
                    "seq": ev.seq,
                    "event_id": ev.event_id,
                    "actor": ev.actor,
                    "kind": "unknown_actor",
                    "detail": f"没有 actor={ev.actor!r} 的公钥,无法验签",
                }
            )
        else:
            ok, reason = verify_event(ev, pem, hub_public_pem)
            if not ok:
                report.ok = False
                report.broken_at_seq = ev.seq
                report.problems.append(
                    {
                        "seq": ev.seq,
                        "event_id": ev.event_id,
                        "actor": ev.actor,
                        "kind": "invalid_event",
                        "detail": reason,
                    }
                )

        prev = ev.hash
        if not report.problems:
            report.verified += 1

    if first_seq is not None:
        report.ranges.append(f"seq {first_seq} → {report.head_seq}")
    return report