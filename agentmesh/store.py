"""存储层:SQLite(WAL)+ 事件溯源投影。

两条硬规则:
  1. 任何状态变化都必须先写事件,再更新投影,且两者在同一个事务里 ——
     所以不存在"改了状态但没有记录"的情况,投影可随时从事件日志重放重建。
  2. 认领(claim)用 UPDATE ... WHERE state='ready' 的条件更新 + BEGIN IMMEDIATE,
     由数据库保证只有一个赢家。并发抢同一任务时失败方拿到 409,不会双份执行。

中心没有 Agent 私钥,所以事件分两层:哈希链由 hub 签,归属由 Agent 的
intent 签名背书。append_event 会强制:属于 Agent 的事件类型必须带 attest_sig,
否则直接抛错,不给"中心代签"留口子。
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .events import (
    AGENT_OWNED_TYPES,
    EV_AGENT_DISABLED,
    EV_AGENT_ENABLED,
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
    genesis_event,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id   TEXT NOT NULL UNIQUE,
    ts         REAL NOT NULL,
    type       TEXT NOT NULL,
    actor      TEXT NOT NULL,
    task_id    TEXT,
    payload    TEXT NOT NULL,
    server     TEXT,
    attest_sig TEXT,
    attest_task_id TEXT,
    prev_hash  TEXT NOT NULL,
    alg        TEXT NOT NULL,
    hash       TEXT NOT NULL,
    sig        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_task ON events(task_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);

CREATE TABLE IF NOT EXISTS agents (
    agent_id         TEXT PRIMARY KEY,
    display_name     TEXT NOT NULL,
    role             TEXT NOT NULL DEFAULT '',
    capabilities     TEXT NOT NULL DEFAULT '[]',
    enabled          INTEGER NOT NULL DEFAULT 1,
    registered_at    REAL NOT NULL,
    last_seen        REAL NOT NULL,
    pubkey_pem       TEXT NOT NULL,
    key_fingerprint  TEXT NOT NULL,
    alg              TEXT NOT NULL DEFAULT 'ed25519',
    tasks_done       INTEGER NOT NULL DEFAULT 0,
    handoffs_given   INTEGER NOT NULL DEFAULT 0,
    handoffs_recv    INTEGER NOT NULL DEFAULT 0,
    meta             TEXT NOT NULL DEFAULT '{}'
);

-- 密钥历史:轮换只新增,不删除。否则换钥之后,换钥之前的事件全部验不过,
-- 审计链会断在最需要它的时候。
CREATE TABLE IF NOT EXISTS agent_keys (
    agent_id        TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    pubkey_pem      TEXT NOT NULL,
    alg             TEXT NOT NULL DEFAULT 'ed25519',
    valid_from_seq  INTEGER NOT NULL,
    valid_to_seq    INTEGER,
    PRIMARY KEY (agent_id, key_fingerprint)
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id             TEXT PRIMARY KEY,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    required_capability TEXT NOT NULL DEFAULT '',
    priority            INTEGER NOT NULL DEFAULT 5,
    state               TEXT NOT NULL DEFAULT 'ready',
    owner               TEXT,
    lease_expires_at    REAL,
    preferred_agent     TEXT,
    preferred_until     REAL,
    context             TEXT NOT NULL DEFAULT '{}',
    result              TEXT NOT NULL DEFAULT '',
    failure_count       INTEGER NOT NULL DEFAULT 0,
    attempt             INTEGER NOT NULL DEFAULT 0,
    created_by          TEXT NOT NULL DEFAULT 'operator',
    created_at          REAL NOT NULL,
    updated_at          REAL NOT NULL,
    due_at              REAL
);
CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state, priority DESC, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_tasks_owner ON tasks(owner);
"""

STATE_READY = "ready"      # 待认领(无人在做)
STATE_CLAIMED = "claimed"  # 执行中(有人持有租约)
STATE_DONE = "done"
STATE_FAILED = "failed"
STATE_CANCELLED = "cancelled"

TASK_STATES = (STATE_READY, STATE_CLAIMED, STATE_DONE, STATE_FAILED, STATE_CANCELLED)


class ConflictError(Exception):
    """条件更新失败 —— 通常意味着别的 Agent 抢先认领了。"""


class NotFound(Exception):
    pass


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class Store:
    def __init__(self, db_path: Path | str, *, hub_signer=None) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.hub_signer = hub_signer
        self._init_schema()

    # ---- 连接管理 ----
    # 每次操作一个连接:FastAPI 同步端点跑在线程池,共享连接会串;
    # WAL 下并发读无锁,开连接极便宜。
    @contextmanager
    def read_conn(self) -> Iterator[sqlite3.Connection]:
        """只读事务的连接。一定关闭。

        ⚠ sqlite3 的 `with conn:` 只管提交/回滚,不会关连接。
        写 `with self.read_conn() as conn:` 看着像上下文管理器,实际每次都漏一个 fd,
        看板开久了会把文件描述符耗光。显式关。
        """
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=8000")
        return conn

    def _init_schema(self) -> None:
        with self.read_conn() as conn:
            conn.executescript(SCHEMA)
            count = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
            if count == 0 and self.hub_signer is not None:
                conn.execute(
                    "INSERT INTO events (seq,event_id,ts,type,actor,task_id,payload,server,"
                    "attest_sig,attest_task_id,prev_hash,alg,hash,sig)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    self._event_row(genesis_event(self.hub_signer)),
                )

    # ---- 事件 ----
    @staticmethod
    def _event_row(ev: Event) -> tuple:
        return (
            ev.seq,
            ev.event_id,
            ev.ts,
            ev.type,
            ev.actor,
            ev.task_id,
            json.dumps(ev.payload, ensure_ascii=False),
            json.dumps(ev.server, ensure_ascii=False),
            ev.attest_sig,
            ev.attest_task_id,
            ev.prev_hash,
            ev.alg,
            ev.hash,
            ev.sig,
        )

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def append_event(
        self,
        conn: sqlite3.Connection,
        *,
        type: str,
        actor: str,
        task_id: str | None = None,
        payload: dict[str, Any] | None = None,
        server: dict[str, Any] | None = None,
        attest_sig: str | None = None,
        attest_task_id: str | None = "",
    ) -> Event:
        """在事务内追加事件。chain 头在同一事务读取,杜绝竞态导致的分叉。"""
        from .events import build_event

        if actor.startswith("agent:") and not attest_sig:
            raise ConflictError(
                f"{type} 的行为者是 Agent({actor}),必须带它私钥签的 payload(attest_sig);"
                "中心没有 Agent 私钥,也不能代签"
            )
        head = conn.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        seq = (head["seq"] + 1) if head else 0
        prev_hash = head["hash"] if head else "0" * 64
        ev = build_event(
            seq=seq,
            type=type,
            actor=actor,
            hub_signer=self.hub_signer,
            prev_hash=prev_hash,
            task_id=task_id,
            payload=payload or {},
            server=server or {},
            attest_sig=attest_sig,
            attest_task_id=attest_task_id,
        )
        conn.execute(
            "INSERT INTO events (seq,event_id,ts,type,actor,task_id,payload,server,attest_sig,"
            "attest_task_id,prev_hash,alg,hash,sig) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            self._event_row(ev),
        )
        return ev

    def get_events(
        self, *, after_seq: int = -1, limit: int = 200, task_id: str | None = None
    ) -> list[Event]:
        conn = self._connect()
        try:
            if task_id:
                rows = conn.execute(
                    "SELECT * FROM events WHERE seq > ? AND task_id = ? ORDER BY seq ASC LIMIT ?",
                    (after_seq, task_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM events WHERE seq > ? ORDER BY seq ASC LIMIT ?",
                    (after_seq, limit),
                ).fetchall()
            return [Event.from_row(dict(r)) for r in rows]
        finally:
            conn.close()

    def count_events(self) -> int:
        with self.read_conn() as conn:
            return int(conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"])

    def head(self) -> tuple[int, str]:
        with self.read_conn() as conn:
            row = conn.execute(
                "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            return (int(row["seq"]), row["hash"]) if row else (-1, "0" * 64)

    # ---- Agent ----
    def register_agent(
        self,
        *,
        agent_id: str,
        display_name: str,
        role: str,
        capabilities: list[str],
        pubkey_pem: str,
        key_fingerprint: str,
        alg: str,
        payload: dict[str, Any],
        attest_sig: str,
        meta: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], Event]:
        """注册或重连。同名不同钥 = 冒充,直接拒绝。"""
        now = time.time()
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if row and row["pubkey_pem"] != pubkey_pem:
                raise ConflictError(
                    f"agent {agent_id} 已用另一把公钥注册(fingerprint "
                    f"{row['key_fingerprint']} ≠ {key_fingerprint});"
                    f"若确为换钥,请显式调用 POST /api/agents/{agent_id}/rotate-key"
                )
            caps_json = json.dumps(capabilities, ensure_ascii=False)
            if row:
                conn.execute(
                    "UPDATE agents SET display_name=?, role=?, capabilities=?, last_seen=?, enabled=1"
                    " WHERE agent_id=?",
                    (display_name, role, caps_json, now, agent_id),
                )
            else:
                conn.execute(
                    "INSERT INTO agents (agent_id,display_name,role,capabilities,enabled,"
                    "registered_at,last_seen,pubkey_pem,key_fingerprint,alg,meta)"
                    " VALUES (?,?,?,?,1,?,?,?,?,?,?)",
                    (
                        agent_id,
                        display_name,
                        role,
                        caps_json,
                        now,
                        now,
                        pubkey_pem,
                        key_fingerprint,
                        alg,
                        json.dumps(meta or {}, ensure_ascii=False),
                    ),
                )
            # payload 必须与 Agent 签名时逐字节一致 —— 服务端一个字节都不改,
            # 否则事后无法用公钥复验。服务端只校验里面声明的指纹与公钥吻合。
            if payload.get("key_fingerprint") != key_fingerprint:
                raise ConflictError(
                    "intent 里的 key_fingerprint 与提交的公钥不符;"
                    "请用同一把私钥签 intent(含公钥指纹)"
                )
            conn.execute(
                "INSERT OR IGNORE INTO agent_keys (agent_id,key_fingerprint,pubkey_pem,alg,"
                "valid_from_seq,valid_to_seq) VALUES (?,?,?,?,?,NULL)",
                (agent_id, key_fingerprint, pubkey_pem, alg, 0),
            )
            ev = self.append_event(
                conn,
                type=EV_AGENT_REGISTERED,
                actor=f"agent:{agent_id}",
                payload=payload,
                attest_sig=attest_sig,
                server={
                    "display_name": display_name,
                    "role": role,
                    "capabilities": capabilities,
                    "key_fingerprint": key_fingerprint,
                    "reconnected": bool(row),
                },
            )
            agent = dict(
                conn.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            )
        return agent, ev

    def rotate_agent_key(
        self, *, agent_id: str, pubkey_pem: str, fingerprint: str, alg: str,
        payload: dict[str, Any], attest_sig: str,
    ) -> Event:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if not row:
                raise NotFound(agent_id)
            conn.execute(
                "UPDATE agents SET pubkey_pem=?, key_fingerprint=?, alg=?, last_seen=?"
                " WHERE agent_id=?",
                (pubkey_pem, fingerprint, alg, time.time(), agent_id),
            )
            head = conn.execute(
                "SELECT COALESCE(MAX(seq), -1) s FROM events"
            ).fetchone()["s"]
            # 旧密钥保留但划上界:它签过的事件仍然是合法历史,不能因为换钥就作废
            conn.execute(
                "UPDATE agent_keys SET valid_to_seq=? WHERE agent_id=? AND valid_to_seq IS NULL",
                (head, agent_id),
            )
            conn.execute(
                "INSERT OR REPLACE INTO agent_keys (agent_id,key_fingerprint,pubkey_pem,alg,"
                "valid_from_seq,valid_to_seq) VALUES (?,?,?,?,?,NULL)",
                (agent_id, fingerprint, pubkey_pem, alg, head),
            )
            ev = self.append_event(
                conn,
                type=EV_AGENT_KEY_ROTATED,
                actor=f"agent:{agent_id}",
                payload=payload,
                attest_sig=attest_sig,
                server={
                    "old_fingerprint": row["key_fingerprint"],
                    "new_fingerprint": fingerprint,
                },
            )
        return ev

    def touch_agent(self, agent_id: str) -> None:
        with self.read_conn() as conn:
            conn.execute(
                "UPDATE agents SET last_seen=? WHERE agent_id=?", (time.time(), agent_id)
            )

    def set_agent_enabled(self, agent_id: str, enabled: bool) -> Event:
        with self.tx() as conn:
            row = conn.execute("SELECT agent_id FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if not row:
                raise NotFound(agent_id)
            conn.execute(
                "UPDATE agents SET enabled=?, last_seen=? WHERE agent_id=?",
                (1 if enabled else 0, time.time(), agent_id),
            )
            ev = self.append_event(
                conn,
                type=EV_AGENT_ENABLED if enabled else EV_AGENT_DISABLED,
                actor="operator",
                payload={"agent_id": agent_id, "enabled": enabled},
            )
        return ev

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        with self.read_conn() as conn:
            row = conn.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            return dict(row) if row else None

    def list_agents(self) -> list[dict[str, Any]]:
        with self.read_conn() as conn:
            return [
                dict(r)
                for r in conn.execute("SELECT * FROM agents ORDER BY registered_at ASC")
            ]

    def known_actors(self) -> dict[str, list[str]]:
        """actor -> 该身份用过的**全部**公钥(当前 + 历史)。

        验签时挨个试:Agent 换过钥之后,旧钥签的事件仍然要能验过,
        否则历史会被误判成伪造 —— 那正好毁掉审计的意义。
        """
        with self.read_conn() as conn:
            out: dict[str, list[str]] = {}
            for r in conn.execute(
                "SELECT agent_id, pubkey_pem FROM agent_keys"
                " UNION SELECT agent_id, pubkey_pem FROM agents"
            ):
                out.setdefault(f"agent:{r['agent_id']}", []).append(r["pubkey_pem"])
            if self.hub_signer is not None:
                pem = self.hub_signer.public_pem().decode()
                out.setdefault("system", [pem])
                out.setdefault("operator", [pem])
            return out

    def current_actor_keys(self) -> dict[str, str]:
        """actor -> **当前**有效公钥。用于鉴权新动作。

        必须和 known_actors 分开:验历史要拿所有旧钥挨个试(否则换钥前的
        合法事件会被误判成伪造),但鉴权新动作只能认当前钥 ——
        否则"因为私钥泄露才换钥"这个动作就毫无意义,泄露的旧钥照样能干活。
        """
        with self.read_conn() as conn:
            out: dict[str, str] = {
                f"agent:{r['agent_id']}": r["pubkey_pem"]
                for r in conn.execute("SELECT agent_id, pubkey_pem FROM agents")
            }
            if self.hub_signer is not None:
                pem = self.hub_signer.public_pem().decode()
                out.setdefault("system", pem)
                out.setdefault("operator", pem)
            return out

    # ---- 任务 ----
    def create_task(
        self,
        *,
        title: str,
        description: str,
        required_capability: str,
        priority: int,
        context: dict[str, Any] | None,
        created_by: str,
        task_id: str | None = None,
        due_at: float | None = None,
        payload: dict[str, Any] | None = None,
        attest_sig: str | None = None,
    ) -> tuple[dict[str, Any], Event]:
        now = time.time()
        tid = task_id or new_id("task")
        # 记下最初要什么能力。交接会把 required_capability 推进到下一步,
        # 不留这个原始值的话,看板上"需求分析"的任务标着 review 会让人以为出错了。
        ctx = dict(context or {})
        ctx.setdefault("_origin_capability", required_capability)
        with self.tx() as conn:
            conn.execute(
                "INSERT INTO tasks (task_id,title,description,required_capability,priority,state,"
                "created_by,created_at,updated_at,context,due_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    tid, title, description, required_capability, priority, STATE_READY,
                    created_by, now, now,
                    json.dumps(ctx, ensure_ascii=False), due_at,
                ),
            )
            ev = self.append_event(
                conn,
                type=EV_TASK_CREATED,
                actor=created_by,
                task_id=tid,
                payload=payload or {},
                attest_sig=attest_sig,
                # Agent 自建任务时,任务 id 是中心刚分配的,Agent 签的是 task_id=None
                attest_task_id=None if created_by.startswith("agent:") else "",
                server={
                    "title": title,
                    "required_capability": required_capability,
                    "priority": priority,
                    "created_by": created_by,
                },
            )
            task = dict(conn.execute("SELECT * FROM tasks WHERE task_id=?", (tid,)).fetchone())
        return task, ev

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self.read_conn() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            return dict(row) if row else None

    def list_tasks(self, state: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        with self.read_conn() as conn:
            if state:
                rows = conn.execute(
                    "SELECT * FROM tasks WHERE state=? ORDER BY priority DESC, created_at ASC LIMIT ?",
                    (state, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]

    def _try_claim(
        self,
        conn: sqlite3.Connection,
        task_id: str,
        agent_id: str,
        lease_seconds: int,
        *,
        enforce_priority_window: bool,
        payload: dict[str, Any],
        attest_sig: str,
        attest_task_id: str | None = "",
    ) -> dict[str, Any] | None:
        """条件更新认领。必须在 tx() 内调用。返回 None 表示没抢到。"""
        now = time.time()
        row = conn.execute(
            "SELECT * FROM tasks WHERE task_id=? AND state=?", (task_id, STATE_READY)
        ).fetchone()
        if not row:
            return None
        # 交接优先窗口:窗口内只让目标 Agent 拿。窗口一过,任何人都能抢 ——
        # 目标 Agent 若在窗口内没来(挂了/忙),任务不会被它永久卡死。
        pref, until = row["preferred_agent"], row["preferred_until"] or 0
        if pref and until > now:
            if enforce_priority_window or pref != agent_id:
                return None

        lease_until = now + lease_seconds
        cur = conn.execute(
            "UPDATE tasks SET state=?, owner=?, lease_expires_at=?, attempt=attempt+1,"
            " updated_at=?, preferred_agent=NULL, preferred_until=NULL"
            " WHERE task_id=? AND state=? AND owner IS NULL",
            (STATE_CLAIMED, agent_id, lease_until, now, task_id, STATE_READY),
        )
        if cur.rowcount != 1:
            return None  # 别人先抢到了

        ev = self.append_event(
            conn,
            type=EV_TASK_CLAIMED,
            actor=f"agent:{agent_id}",
            task_id=task_id,
            payload=payload,
            attest_sig=attest_sig,
            attest_task_id=attest_task_id,
            server={
                "attempt": int(row["attempt"]) + 1,
                "lease_seconds": lease_seconds,
                "lease_expires_at": lease_until,
                "required_capability": row["required_capability"],
                "from_handoff": pref == agent_id and until > now,
            },
        )
        task = dict(conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone())
        task["_last_event"] = ev
        return task

    def claim_task(
        self, task_id: str, agent_id: str, lease_seconds: int, *,
        payload: dict[str, Any], attest_sig: str
    ) -> tuple[dict[str, Any] | None, str]:
        with self.tx() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                return None, "not_found"
            if row["state"] == STATE_CLAIMED and (row["lease_expires_at"] or 0) > time.time():
                return None, "already_claimed"
            task = self._try_claim(
                conn, task_id, agent_id, lease_seconds,
                enforce_priority_window=True, payload=payload, attest_sig=attest_sig,
            )
            return task, "" if task else "conflict"

    def claim_next(
        self,
        agent_id: str,
        capabilities: list[str],
        lease_seconds: int,
        *,
        handoff_priority_seconds: int = 25,
        payload_factory=None,
        attest_sig: str | None = None,
    ) -> dict[str, Any] | None:
        """认领下一个能做的任务 —— "无中心调度"的落点。

        Agent 自己来问"有没有我能干的活",中心不指派、不知道谁擅长什么,
        只做能力过滤和原子认领。排序规则:
          1. 交接给我的(窗口内)优先
          2. 其余按 priority 降序、创建时间升序(FIFO)
        全部在一个事务里逐个条件更新尝试,并发抢占由数据库裁决。
        """
        now = time.time()
        caps = {c.lower() for c in capabilities if c}
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT task_id, required_capability, preferred_agent, preferred_until, priority"
                " FROM tasks WHERE state=? ORDER BY priority DESC, created_at ASC",
                (STATE_READY,),
            ).fetchall()
            handoff_first: list[sqlite3.Row] = []
            normal: list[sqlite3.Row] = []
            for r in rows:
                need = (r["required_capability"] or "").lower()
                if need and need not in caps:
                    continue  # 能力不匹配,不参与竞速
                pref, until = r["preferred_agent"], r["preferred_until"] or 0
                if pref == agent_id and until > now:
                    handoff_first.append(r)
                elif pref and until > now:
                    continue  # 交接给别人且窗口未过,尊重它
                else:
                    normal.append(r)

            for r in handoff_first + normal:
                task_id = r["task_id"]
                claim_payload = (
                    payload_factory(task_id, dict(r)) if payload_factory
                    else {"op": "claim_next", "agent_id": agent_id}
                )
                task = self._try_claim(
                    conn, task_id, agent_id, lease_seconds,
                    enforce_priority_window=False, payload=claim_payload, attest_sig=attest_sig,
                    # 关键:Agent 请求认领时还不知道会是哪条任务,
                    # 所以归属签名对应的是 task_id=None,这里必须如实记录,
                    # 否则事后复验会拿错 task_id 把诚实的认领判成伪造。
                    attest_task_id=None,
                )
                if task:
                    return task
        return None

    def renew_lease(self, task_id: str, agent_id: str, lease_seconds: int) -> dict[str, Any] | None:
        now = time.time()
        with self.tx() as conn:
            cur = conn.execute(
                "UPDATE tasks SET lease_expires_at=?, updated_at=? WHERE task_id=? AND owner=?"
                " AND state=?",
                (now + lease_seconds, now, task_id, agent_id, STATE_CLAIMED),
            )
            if cur.rowcount != 1:
                return None
            return dict(conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone())

    def record_progress(
        self, task_id: str, agent_id: str, *, payload: dict[str, Any], attest_sig: str
    ) -> tuple[dict[str, Any], Event]:
        with self.tx() as conn:
            row = conn.execute("SELECT owner FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row or row["owner"] != agent_id:
                raise ConflictError("只有任务持有者可以上报进度")
            ev = self.append_event(
                conn,
                type=EV_TASK_PROGRESS,
                actor=f"agent:{agent_id}",
                task_id=task_id,
                payload=payload,
                attest_sig=attest_sig,
            )
            conn.execute("UPDATE tasks SET updated_at=? WHERE task_id=?", (time.time(), task_id))
            task = dict(conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone())
        return task, ev

    def handoff_task(
        self,
        *,
        task_id: str,
        from_agent: str,
        to_agent: str,
        next_capability: str,
        reason: str,
        note: str,
        context: dict[str, Any] | None,
        payload: dict[str, Any],
        attest_sig: str,
        handoff_priority_seconds: int,
    ) -> tuple[dict[str, Any], Event]:
        with self.tx() as conn:
            row = conn.execute(
                "SELECT * FROM tasks WHERE task_id=? AND owner=? AND state=?",
                (task_id, from_agent, STATE_CLAIMED),
            ).fetchone()
            if not row:
                raise ConflictError("只有当前持有租约的 Agent 可以交接该任务")

            target = conn.execute(
                "SELECT agent_id, enabled FROM agents WHERE agent_id=?", (to_agent,)
            ).fetchone()
            if not target:
                raise NotFound(f"目标 Agent {to_agent} 不在花名册中")
            if not target["enabled"]:
                raise ConflictError(f"目标 Agent {to_agent} 已被禁用,无法交接")
            if to_agent == from_agent:
                raise ConflictError("不能交接给自己")
            # 签名归签名,请求归请求:签名的内容里说交给谁、下一步需要什么能力,
            # 就必须真的这么请求。否则会出现"签的是 A、实际交给 B"的错位。
            signed_to = (payload or {}).get("to")
            signed_task = (payload or {}).get("task_id")
            signed_from = (payload or {}).get("from")
            signed_next = (payload or {}).get("next_capability", "")
            if signed_to != to_agent or signed_task != task_id or signed_from != from_agent:
                raise ConflictError(
                    "签名内容里的 from/to/task_id 与请求不一致,拒收(签名必须与行为对应)"
                )
            if signed_next != next_capability:
                raise ConflictError("签名内容里的 next_capability 与请求不一致,拒收")

            now = time.time()
            merged = json.loads(row["context"] or "{}")
            merged.update(context or {})
            # 交接释放租约、回队列;目标 Agent 在窗口内优先领取。
            # 不是"派给某个进程",所以目标掉线也不会让任务卡死。
            # 交接的同时把"这一步需要什么能力"推进到下一步 ——
            # 否则任务还挂着上一个能力的要求,接手的人能力对不上,永远领不到,
            # 任务就在队列里干等直到租约过期。能力跃迁写进签名,可追溯。
            new_required = next_capability or row["required_capability"]
            conn.execute(
                "UPDATE tasks SET state=?, owner=NULL, lease_expires_at=NULL, preferred_agent=?,"
                " preferred_until=?, context=?, updated_at=?, required_capability=?"
                " WHERE task_id=?",
                (
                    STATE_READY, to_agent, now + handoff_priority_seconds,
                    json.dumps(merged, ensure_ascii=False), now, new_required, task_id,
                ),
            )
            conn.execute(
                "UPDATE agents SET handoffs_given=handoffs_given+1 WHERE agent_id=?", (from_agent,)
            )
            conn.execute(
                "UPDATE agents SET handoffs_recv=handoffs_recv+1 WHERE agent_id=?", (to_agent,)
            )
            ev = self.append_event(
                conn,
                type=EV_TASK_HANDED_OFF,
                actor=f"agent:{from_agent}",
                task_id=task_id,
                payload=payload,
                attest_sig=attest_sig,
                server={
                    "reason": reason,
                    "note": note,
                    "priority_window_seconds": handoff_priority_seconds,
                    "from": from_agent,
                    "to": to_agent,
                    "capability_from": row["required_capability"],
                    "capability_to": new_required,
                },
            )
            task = dict(conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone())
        return task, ev

    def complete_task(
        self,
        task_id: str,
        agent_id: str,
        result: str,
        artifacts: list[str],
        *,
        payload: dict[str, Any],
        attest_sig: str,
    ) -> tuple[dict[str, Any], Event]:
        with self.tx() as conn:
            row = conn.execute("SELECT owner FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row or row["owner"] != agent_id:
                raise ConflictError("只有任务持有者可以完成任务")
            conn.execute(
                "UPDATE tasks SET state=?, result=?, owner=NULL, lease_expires_at=NULL,"
                " preferred_agent=NULL, preferred_until=NULL, updated_at=? WHERE task_id=?",
                (STATE_DONE, result, time.time(), task_id),
            )
            conn.execute(
                "UPDATE agents SET tasks_done=tasks_done+1 WHERE agent_id=?", (agent_id,)
            )
            ev = self.append_event(
                conn,
                type=EV_TASK_COMPLETED,
                actor=f"agent:{agent_id}",
                task_id=task_id,
                payload=payload,
                attest_sig=attest_sig,
                server={"artifacts": artifacts, "result_len": len(result)},
            )
            task = dict(conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone())
        return task, ev

    def fail_task(
        self,
        task_id: str,
        agent_id: str,
        error: str,
        *,
        requeue: bool,
        payload: dict[str, Any],
        attest_sig: str,
    ) -> tuple[dict[str, Any], Event]:
        with self.tx() as conn:
            row = conn.execute(
                "SELECT owner, failure_count FROM tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if not row or row["owner"] != agent_id:
                raise ConflictError("只有任务持有者可以标记失败")
            now = time.time()
            # 毒任务防护:同样的任务反复失败,重排到队列里只会无限循环烧 CPU,
            # 超过上限就落到 failed,等人来看 —— 自动化不等于不管不顾。
            MAX_ATTEMPTS = 5
            will_requeue = requeue and (row["failure_count"] + 1) < MAX_ATTEMPTS
            conn.execute(
                "UPDATE tasks SET state=?, owner=NULL, lease_expires_at=NULL,"
                " preferred_agent=NULL, preferred_until=NULL,"
                " failure_count=failure_count+1, updated_at=? WHERE task_id=?",
                (STATE_READY if will_requeue else STATE_FAILED, now, task_id),
            )
            ev = self.append_event(
                conn,
                type=EV_TASK_FAILED,
                actor=f"agent:{agent_id}",
                task_id=task_id,
                payload=payload,
                attest_sig=attest_sig,
                server={
                    "requeued": will_requeue,
                    "failure_count": row["failure_count"] + 1,
                    "max_failures": MAX_ATTEMPTS,
                    "abandoned": bool(requeue and not will_requeue),
                },
            )
            task = dict(conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone())
        return task, ev

    def release_expired_leases(self) -> list[tuple[str, str]]:
        """回收过期租约:Agent 崩溃/断网的任务自动回到队列。"""
        now = time.time()
        released: list[tuple[str, str]] = []
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT task_id, owner FROM tasks WHERE state=? AND lease_expires_at IS NOT NULL"
                " AND lease_expires_at < ?",
                (STATE_CLAIMED, now),
            ).fetchall()
            for r in rows:
                conn.execute(
                    "UPDATE tasks SET state=?, owner=NULL, lease_expires_at=NULL, preferred_agent=NULL,"
                    " preferred_until=NULL, updated_at=? WHERE task_id=? AND state=?",
                    (STATE_READY, now, r["task_id"], STATE_CLAIMED),
                )
                self.append_event(
                    conn,
                    type=EV_TASK_RELEASED,
                    actor="system",
                    task_id=r["task_id"],
                    payload={
                        "reason": "lease_expired",
                        "previous_owner": r["owner"],
                        "note": f"{r['owner']} 未在租约内续租,任务自动回到队列",
                    },
                )
                released.append((r["task_id"], r["owner"]))
        return released

    def cancel_task(self, task_id: str) -> tuple[dict[str, Any], Event]:
        with self.tx() as conn:
            row = conn.execute("SELECT state FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise NotFound(task_id)
            conn.execute(
                "UPDATE tasks SET state=?, owner=NULL, lease_expires_at=NULL,"
                " preferred_agent=NULL, preferred_until=NULL, updated_at=? WHERE task_id=?",
                (STATE_CANCELLED, time.time(), task_id),
            )
            ev = self.append_event(
                conn,
                type=EV_TASK_FAILED,
                actor="operator",
                task_id=task_id,
                payload={"error": "operator_cancelled", "cancelled": True},
            )
            task = dict(conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone())
        return task, ev

    def stats(self) -> dict[str, Any]:
        with self.read_conn() as conn:
            task_states = {
                r["state"]: r["c"]
                for r in conn.execute("SELECT state, COUNT(*) c FROM tasks GROUP BY state")
            }
            agents = conn.execute(
                "SELECT COUNT(*) total, SUM(enabled) enabled FROM agents"
            ).fetchone()
            online = conn.execute(
                "SELECT COUNT(*) c FROM agents WHERE last_seen > ?", (time.time() - 15,)
            ).fetchone()["c"]
            claimed = conn.execute(
                "SELECT COUNT(*) c FROM tasks WHERE state=?", (STATE_CLAIMED,)
            ).fetchone()["c"]
            return {
                "tasks": task_states,
                "agents_total": agents["total"] or 0,
                "agents_enabled": agents["enabled"] or 0,
                "agents_online": online,
                "tasks_in_flight": claimed,
                "events": self.count_events(),
            }


def intent_of_handoff(
    from_agent: str, task_id: str, to_agent: str, reason: str, note: str,
    context: dict[str, Any] | None,
) -> dict[str, Any]:
    """交接 intent 的规范结构 —— Agent 签名时和中心记录时必须一致。"""
    return {
        "op": "handoff",
        "task_id": task_id,
        "from": from_agent,
        "to": to_agent,
        "reason": reason,
        "note": note[:200],
        "context": context or {},
    }