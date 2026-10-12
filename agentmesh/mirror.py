"""Agent 本地事件镜像。

这是"去中心化"能不能落地的那一块:每个 Agent 自己留一份完整事件日志副本,
收到新事件时**先本地校验再入库**。于是:

  - 中心可以拒绝服务、可以撒谎说"某个任务完成了",但它伪造不了一条带
    Agent 私钥签名的意图 —— Agent 拉下来一验就知道对不上,记入本地异议日志;
  - 中心整个挂了,Agent 手里仍有完整历史,可以离线验、可以留着;
  - 事后审计不依赖中心配合:拿 SQLite 文件 + 公钥目录就能验。

镜像不是备份,是"独立复核"。所以校验必须在这里真的做,不能只存不验。
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from .events import Event, verify_chain

MIRROR_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY,
    event_id   TEXT NOT NULL,
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
CREATE TABLE IF NOT EXISTS disputes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    seq       INTEGER,
    reason    TEXT NOT NULL,
    detail    TEXT NOT NULL
);
-- 同一身份可能换过多次钥,所以是"一把一行"而不是"一人一行"。
-- 否则轮换后旧钥被覆盖,本地镜像会把自己签过的事件判成伪造。
CREATE TABLE IF NOT EXISTS peers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id   TEXT NOT NULL,
    pem        TEXT NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE (agent_id, pem)
);
"""


class Mirror:
    def __init__(self, db_path: Path | str, agent_id: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.agent_id = agent_id
        self.hub_pem: str | None = None
        with self._conn() as c:
            c.executescript(MIRROR_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    # ---- 信任材料 ----
    def set_hub_key(self, pem: str) -> None:
        self.hub_pem = pem

    def upsert_peer_key(self, agent_id: str, pem: str) -> None:
        """记录同伴的公钥。没有公钥就无法验证对方的行为,只能存不能信。

        同一身份多把公钥并存 —— 换钥不清历史,否则本地镜像会误判。
        """
        with self._conn() as c:
            c.execute(
                "INSERT INTO peers (agent_id,pem,updated_at) VALUES (?,?,?)"
                " ON CONFLICT(agent_id, pem) DO UPDATE SET updated_at=excluded.updated_at",
                (agent_id, pem, time.time()),
            )

    def _pubkeys(self) -> dict[str, list[str]]:
        """actor -> 该身份的全部公钥(换过钥就有多把)。"""
        out: dict[str, list[str]] = {}
        with self._conn() as c:
            for r in c.execute("SELECT agent_id,pem FROM peers"):
                out.setdefault(f"agent:{r['agent_id']}", []).append(r["pem"])
        if self.hub_pem:
            out.setdefault("system", [self.hub_pem])
            out.setdefault("operator", [self.hub_pem])
        return out

    # ---- 入库(先验后存) ----
    def sync(self, raw_events: list[dict[str, Any]], *, stop_on_error: bool = True) -> dict[str, Any]:
        """把中心推来的事件逐条本地校验后入库。

        校验失败 → 写 disputes 表、**不写入 events 表**,并返回报告。
        stop_on_error=True 时立即停止(后续事件的链接关系已经无从校验)。
        """
        accepted = 0
        rejected: list[dict[str, Any]] = []
        conn = self._conn()
        try:
            for raw in raw_events:
                ev = Event.from_row(raw)
                report = verify_chain(
                    [ev],
                    lambda a: self._pubkeys().get(a),
                    expected_prev_hash=ev.prev_hash,  # 单条:不与本地对比链接,只验自身
                    check_link=False,
                    hub_public_pem=self.hub_pem.encode() if self.hub_pem else None,
                )
                if not report.ok:
                    reason = "; ".join(p["detail"] for p in report.problems)
                    conn.execute(
                        "INSERT INTO disputes (ts,seq,reason,detail) VALUES (?,?,?,?)",
                        (time.time(), ev.seq, "verify_failed", reason),
                    )
                    rejected.append({"seq": ev.seq, "reason": reason})
                    if stop_on_error:
                        break
                    continue
                conn.execute(
                    "INSERT OR IGNORE INTO events (seq,event_id,ts,type,actor,task_id,payload,"
                    "server,attest_sig,attest_task_id,prev_hash,alg,hash,sig)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        ev.seq, ev.event_id, ev.ts, ev.type, ev.actor, ev.task_id,
                        json.dumps(ev.payload, ensure_ascii=False),
                        json.dumps(ev.server, ensure_ascii=False),
                        ev.attest_sig, ev.attest_task_id,
                        ev.prev_hash, ev.alg, ev.hash, ev.sig,
                    ),
                )
                accepted += 1
        finally:
            conn.close()
        return {"accepted": accepted, "rejected": rejected}

    def head_seq(self) -> int:
        with self._conn() as c:
            row = c.execute("SELECT MAX(seq) s FROM events").fetchone()
            return int(row["s"]) if row and row["s"] is not None else -1

    def all_events(self) -> list[Event]:
        with self._conn() as c:
            return [Event.from_row(dict(r)) for r in c.execute("SELECT * FROM events ORDER BY seq ASC")]

    def disputes(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn() as c:
            return [
                dict(r)
                for r in c.execute(
                    "SELECT * FROM disputes ORDER BY id DESC LIMIT ?", (limit,)
                )
            ]

    def verify_local(self) -> dict[str, Any]:
        """离线复验本地整条镜像链 —— 不问中心一句。"""
        report = verify_chain(
            self.all_events(),
            lambda a: self._pubkeys().get(a),
            expected_prev_hash="0" * 64,
            check_link=True,
            hub_public_pem=self.hub_pem.encode() if self.hub_pem else None,
        )
        return report.to_dict()

    def stats(self) -> dict[str, Any]:
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
            disputes = c.execute("SELECT COUNT(*) n FROM disputes").fetchone()["n"]
            peers = c.execute("SELECT COUNT(*) n FROM peers").fetchone()["n"]
        return {
            "agent_id": self.agent_id,
            "mirrored_events": total,
            "disputes": disputes,
            "known_peers": peers,
            "hub_key": bool(self.hub_pem),
            "db": str(self.db_path),
        }