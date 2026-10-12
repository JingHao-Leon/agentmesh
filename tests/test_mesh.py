"""端到端测试。用标准库 unittest,不需要 pytest —— 少一个装不上的依赖。

    python -m unittest discover -s tests -v
    ./run_tests.sh

覆盖的是"这个系统宣称的性质到底成不成立":
  - 哈希链能不能发现改一个字节
  - 中心失陷后能不能伪造 Agent 的行为
  - 并发抢同一个任务,是不是只有一个赢家
  - Agent 崩了,任务会不会永远卡住
  - 交接后能力需求有没有跟着推进
  - Agent 本地镜像能不能独立验出中心的问题
"""

from __future__ import annotations

import json
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

import httpx

from agentmesh.events import (
    EV_TASK_CLAIMED,
    EV_TASK_COMPLETED,
    EV_TASK_HANDED_OFF,
    EV_TASK_PROGRESS,
    build_event,
    compute_hash,
    signed_payload_bytes,
    verify_chain,
)
from agentmesh.config import reset_settings
from agentmesh.mirror import Mirror
from agentmesh.signing import canonical_json, load_or_create_signer
from agentmesh.store import STATE_CLAIMED, STATE_READY, ConflictError, Store


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agentmesh-test-"))
        self.hub = load_or_create_signer(self.tmp / "hub.pem")
        self.store = Store(self.tmp / "mesh.db", hub_signer=self.hub)
        self.actors: dict[str, object] = {}

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- 造一个 Agent ----
    def make_agent(self, agent_id: str, name: str = "", caps: list[str] | None = None):
        signer = load_or_create_signer(self.tmp / "agents" / f"{agent_id}.pem")
        actor = f"agent:{agent_id}"
        self.actors[actor] = signer
        payload = {
            "op": "register",
            "agent_id": agent_id,
            "display_name": name or agent_id,
            "capabilities": caps or [],
            "key_fingerprint": signer.public_identity(),
        }
        self.store.register_agent(
            agent_id=agent_id,
            display_name=name or agent_id,
            role="",
            capabilities=caps or [],
            pubkey_pem=signer.public_pem().decode(),
            key_fingerprint=signer.public_identity(),
            alg=signer.algorithm,
            payload=payload,
            attest_sig=signer.sign(signed_payload_bytes(actor, "agent.registered", None, payload)),
        )
        return actor, signer

    def sign(self, actor: str, type_: str, task_id: str | None, payload: dict) -> str:
        return self.actors[actor].sign(signed_payload_bytes(actor, type_, task_id, payload))

    def make_task(self, title="T", cap="analyze", priority=5, **kw):
        task, _ = self.store.create_task(
            title=title, description="", required_capability=cap, priority=priority,
            context=kw.get("context"), created_by="operator",
        )
        return task

    def verify(self) -> dict:
        return verify_chain(
            self.store.get_events(after_seq=-1, limit=10000),
            lambda a: self.store.known_actors().get(a),
            expected_prev_hash="0" * 64,
            check_link=True,
            hub_public_pem=self.hub.public_pem(),
        ).to_dict()


# ====================================================================
class TestChainIntegrity(Base):
    def test_clean_chain_passes(self):
        self.make_agent("a1", "甲", ["analyze"])
        t = self.make_task("活儿")
        p = {"op": "claim_next", "agent_id": "a1", "capabilities": ["analyze"]}
        self.store.claim_next("a1", ["analyze"], 30, payload_factory=lambda *_: p,
                              attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, None, p))
        r = self.verify()
        self.assertTrue(r["ok"], r["problems"])

    def test_claim_next_uses_task_id_none_for_signature(self):
        """认领时 Agent 不知道会是哪条任务,签名对应的 task_id 必须是 None。"""
        self.make_agent("a1", "甲", ["analyze"])
        self.make_task("活儿", "analyze")
        p = {"op": "claim_next", "agent_id": "a1", "capabilities": ["analyze"]}
        self.store.claim_next("a1", ["analyze"], 30, payload_factory=lambda *_: p,
                              attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, None, p))
        self.assertTrue(self.verify()["ok"], self.verify()["problems"])

    def test_tampered_payload_is_caught(self):
        self.make_agent("a1", "甲", ["analyze"])
        self.make_task("活儿", "analyze")
        p = {"op": "claim_next", "agent_id": "a1", "capabilities": ["analyze"]}
        self.store.claim_next("a1", ["analyze"], 30, payload_factory=lambda *_: p,
                              attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, None, p))
        ev = self.store.get_events(after_seq=-1)[-1]
        forged = dict(ev.payload, note="我其实没做")
        broken = build_event(
            seq=ev.seq, type=ev.type, actor=ev.actor, hub_signer=self.hub,
            prev_hash=ev.prev_hash, task_id=ev.task_id, payload=forged,
            server=ev.server, attest_sig=ev.attest_sig, attest_task_id=ev.attest_task_id,
            ts=ev.ts, event_id=ev.event_id,
        )
        report = verify_chain(
            [broken], lambda a: self.store.known_actors().get(a), check_link=False,
            hub_public_pem=self.hub.public_pem(),
        ).to_dict()
        self.assertFalse(report["ok"])

    def test_hub_cannot_forge_agent_action(self):
        """即使攻击者拿到中心私钥、能重算 hash 和中心签名,也造不出 Agent 的行为。"""
        self.make_agent("a1", "甲", ["analyze"])
        t = self.make_task("活儿", "analyze")
        p = {"op": "claim", "task_id": t["task_id"], "agent_id": "a1"}
        self.store.claim_task(t["task_id"], "a1", 30, payload=p,
                              attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, t["task_id"], p))
        ev = self.store.get_events(after_seq=-1)[-1]
        forged_payload = dict(ev.payload, result="伪造:任务其实失败了")

        # 用中心私钥把 hash 与中心签名都重算到自洽
        body = {
            "seq": ev.seq, "event_id": ev.event_id, "ts": ev.ts, "type": ev.type,
            "actor": ev.actor, "task_id": ev.task_id, "payload": forged_payload,
            "server": ev.server, "attest_sig": ev.attest_sig,
            "attest_task_id": ev.attest_task_id, "alg": ev.alg,
        }
        h = compute_hash(ev.prev_hash, body)
        hub_sig = self.hub.sign(canonical_json({"prev_hash": ev.prev_hash, **body}))
        forged = build_event(
            seq=ev.seq, type=ev.type, actor=ev.actor, hub_signer=self.hub,
            prev_hash=ev.prev_hash, task_id=ev.task_id, payload=forged_payload,
            server=ev.server, attest_sig=ev.attest_sig, attest_task_id=ev.attest_task_id,
            ts=ev.ts, event_id=ev.event_id,
        )
        forged.hash, forged.sig = h, hub_sig
        forged.prev_hash = ev.prev_hash

        report = verify_chain(
            [forged], lambda a: self.store.known_actors().get(a), check_link=False,
            hub_public_pem=self.hub.public_pem(),
        ).to_dict()
        self.assertFalse(report["ok"], "内容被中心改写却通过了校验 —— 这是致命漏洞")
        self.assertTrue(any("签名" in x["detail"] for x in report["problems"]))

    def test_deleting_an_event_breaks_the_link(self):
        self.make_agent("a1", "甲", ["analyze"])
        for i in range(3):
            self.make_task(f"活儿{i}", "analyze")
            p = {"op": "claim_next", "agent_id": "a1", "capabilities": ["analyze"]}
            self.store.claim_next("a1", ["analyze"], 30, payload_factory=lambda *_: p,
                                  attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, None, p))
        events = self.store.get_events(after_seq=-1)
        del events[2]
        report = verify_chain(events, lambda a: self.store.known_actors().get(a),
                              expected_prev_hash="0" * 64,
                              hub_public_pem=self.hub.public_pem()).to_dict()
        self.assertFalse(report["ok"])
        self.assertTrue(any(x["kind"] == "broken_link" for x in report["problems"]))

    def test_agent_event_without_signature_is_rejected(self):
        """绕过接口直接写库,中心也不能替 Agent 签。"""
        self.make_agent("a1", "甲", ["analyze"])
        t = self.make_task("活儿", "analyze")
        with self.assertRaises(ConflictError):
            self.store.claim_task(t["task_id"], "a1", 30, payload={"op": "claim"},
                                  attest_sig=None)


# ====================================================================
class TestClaiming(Base):
    def test_only_one_agent_wins_the_same_task(self):
        self.make_agent("a1", "甲", ["analyze"])
        self.make_agent("a2", "乙", ["analyze"])
        t = self.make_task("抢手活儿", "analyze")
        winners, errors = [], []
        barrier = threading.Barrier(2)

        def grab(agent_id):
            barrier.wait()
            p = {"op": "claim", "task_id": t["task_id"], "agent_id": agent_id}
            try:
                task, reason = self.store.claim_task(
                    t["task_id"], agent_id, 30, payload=p,
                    attest_sig=self.sign(f"agent:{agent_id}", EV_TASK_CLAIMED, t["task_id"], p),
                )
                (winners.append(agent_id) if task else errors.append(reason))
            except ConflictError as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=grab, args=(a,)) for a in ("a1", "a2")]
        [x.start() for x in threads]
        [x.join() for x in threads]
        self.assertEqual(len(winners), 1, f"并发认领出现 {len(winners)} 个赢家")
        self.assertTrue(self.verify()["ok"])

    def test_capability_filter(self):
        self.make_agent("writer", "写手", ["docs"])
        self.make_task("要设计", "design")
        p = {"op": "claim_next", "agent_id": "writer", "capabilities": ["docs"]}
        got = self.store.claim_next("writer", ["docs"], 30, payload_factory=lambda *_: p,
                                    attest_sig=self.sign("agent:writer", EV_TASK_CLAIMED, None, p))
        self.assertIsNone(got, "能力不匹配却领到了任务")

    def test_priority_then_fifo(self):
        self.make_agent("a1", "甲", ["analyze"])
        self.make_task("低优先", "analyze", priority=2)
        self.make_task("高优先", "analyze", priority=9)
        p = {"op": "claim_next", "agent_id": "a1", "capabilities": ["analyze"]}
        got = self.store.claim_next("a1", ["analyze"], 30, payload_factory=lambda *_: p,
                                    attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, None, p))
        self.assertEqual(got["title"], "高优先")

    def test_expired_lease_returns_task_to_queue(self):
        """Agent 崩了不能把任务永远卡住 —— 没有中心来救,租约自己会到期。"""
        self.make_agent("a1", "甲", ["analyze"])
        self.make_agent("a2", "乙", ["analyze"])
        t = self.make_task("会崩的活儿", "analyze")
        p = {"op": "claim", "task_id": t["task_id"], "agent_id": "a1"}
        self.store.claim_task(t["task_id"], "a1", 1, payload=p,
                              attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, t["task_id"], p))
        time.sleep(1.2)
        released = self.store.release_expired_leases()
        self.assertEqual(released, [(t["task_id"], "a1")])
        self.assertEqual(self.store.get_task(t["task_id"])["state"], STATE_READY)

        p2 = {"op": "claim_next", "agent_id": "a2", "capabilities": ["analyze"]}
        got = self.store.claim_next("a2", ["analyze"], 30, payload_factory=lambda *_: p2,
                                    attest_sig=self.sign("agent:a2", EV_TASK_CLAIMED, None, p2))
        self.assertIsNotNone(got, "任务回收后没人能再领")
        self.assertEqual(got["attempt"], 2)
        self.assertTrue(self.verify()["ok"])

    def test_only_owner_can_complete(self):
        self.make_agent("a1", "甲", ["analyze"])
        self.make_agent("a2", "乙", ["analyze"])
        t = self.make_task("活儿", "analyze")
        p = {"op": "claim", "task_id": t["task_id"], "agent_id": "a1"}
        self.store.claim_task(t["task_id"], "a1", 30, payload=p,
                              attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, t["task_id"], p))
        p2 = {"op": "complete", "task_id": t["task_id"]}
        with self.assertRaises(ConflictError):
            self.store.complete_task(t["task_id"], "a2", "抢功", [], payload=p2,
                                     attest_sig=self.sign("agent:a2", EV_TASK_COMPLETED, t["task_id"], p2))

    def test_poison_task_stops_being_requeued_forever(self):
        self.make_agent("a1", "甲", ["analyze"])
        t = self.make_task("毒任务", "analyze")
        for i in range(5):
            p = {"op": "claim", "task_id": t["task_id"], "agent_id": "a1"}
            self.store.claim_task(t["task_id"], "a1", 30, payload=p,
                                  attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, t["task_id"], p))
            self.store.fail_task(t["task_id"], "a1", "炸了", requeue=True, payload=p,
                                 attest_sig=self.sign("agent:a1", "task.failed", t["task_id"], p))
        self.assertEqual(self.store.get_task(t["task_id"])["state"], "failed")


# ====================================================================
class TestHandoff(Base):
    def setup_two(self):
        self.make_agent("a1", "甲", ["analyze"])
        self.make_agent("a2", "乙", ["design"])
        t = self.make_task("要交接的活儿", "analyze")
        p = {"op": "claim", "task_id": t["task_id"], "agent_id": "a1"}
        self.store.claim_task(t["task_id"], "a1", 30, payload=p,
                              attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, t["task_id"], p))
        return t

    def do_handoff(self, t, to="a2", next_cap="design"):
        payload = {
            "op": "handoff", "task_id": t["task_id"], "from": "a1", "to": to,
            "next_capability": next_cap, "reason": "该设计了", "note": "接着来",
            "context": {},
        }
        return self.store.handoff_task(
            task_id=t["task_id"], from_agent="a1", to_agent=to, next_capability=next_cap,
            reason="该设计了", note="接着来", context={}, payload=payload,
            attest_sig=self.sign("agent:a1", EV_TASK_HANDED_OFF, t["task_id"], payload),
            handoff_priority_seconds=25,
        )

    def test_handoff_advances_required_capability(self):
        """交接后能力需求必须跟着推进,否则接手的人匹配不上,任务会干等到超时。"""
        t = self.setup_two()
        self.do_handoff(t)
        task = self.store.get_task(t["task_id"])
        self.assertEqual(task["required_capability"], "design")
        self.assertEqual(task["state"], STATE_READY)
        self.assertEqual(task["preferred_agent"], "a2")

    def test_designated_agent_gets_priority(self):
        t = self.setup_two()
        self.do_handoff(t)
        p = {"op": "claim_next", "agent_id": "a2", "capabilities": ["design"]}
        got = self.store.claim_next("a2", ["design"], 30, payload_factory=lambda *_: p,
                                    attest_sig=self.sign("agent:a2", EV_TASK_CLAIMED, None, p))
        self.assertIsNotNone(got)
        self.assertTrue(got["_last_event"].payload is not None)
        self.assertTrue(self.verify()["ok"])

    def test_priority_window_expires_so_task_is_not_stuck(self):
        """指名的人不来领,窗口一过其他人就该能接,否则任务被点名对象永久卡死。"""
        self.make_agent("a3", "丙", ["analyze"])
        t = self.setup_two()
        self.do_handoff(t, next_cap="analyze")  # 指名给 a2(只会 design),但下一步需要 analyze

        # 直接把优先窗口调到过去,模拟"被点名的人一直没来"
        with self.store.tx() as conn:
            conn.execute(
                "UPDATE tasks SET preferred_until=? WHERE task_id=?",
                (time.time() - 1, t["task_id"]),
            )

        p = {"op": "claim_next", "agent_id": "a3", "capabilities": ["analyze"]}
        got = self.store.claim_next("a3", ["analyze"], 30, payload_factory=lambda *_: p,
                                    attest_sig=self.sign("agent:a3", EV_TASK_CLAIMED, None, p))
        self.assertIsNotNone(got, "交接优先窗口过期后任务被卡死了")
        self.assertEqual(got["owner"], "a3")

    def test_signed_target_must_match_request(self):
        """签名里说交给 a2,请求里却交给别人 —— 必须拒收。"""
        t = self.setup_two()
        payload = {
            "op": "handoff", "task_id": t["task_id"], "from": "a1", "to": "a1",
            "next_capability": "design", "reason": "x", "note": "", "context": {},
        }
        with self.assertRaises(ConflictError):
            self.store.handoff_task(
                task_id=t["task_id"], from_agent="a1", to_agent="a2", next_capability="design",
                reason="x", note="", context={}, payload=payload,
                attest_sig=self.sign("agent:a1", EV_TASK_HANDED_OFF, t["task_id"], payload),
                handoff_priority_seconds=25,
            )

    def test_cannot_handoff_to_disabled_agent(self):
        t = self.setup_two()
        self.store.set_agent_enabled("a2", False)
        with self.assertRaises(ConflictError):
            self.do_handoff(t)

    def test_handoff_chain_is_fully_traced(self):
        t = self.setup_two()
        self.do_handoff(t)
        p = {"op": "claim_next", "agent_id": "a2", "capabilities": ["design"]}
        self.store.claim_next("a2", ["design"], 30, payload_factory=lambda *_: p,
                              attest_sig=self.sign("agent:a2", EV_TASK_CLAIMED, None, p))
        timeline = self.store.get_events(after_seq=-1, limit=100, task_id=t["task_id"])
        kinds = [e.type for e in timeline]
        self.assertIn(EV_TASK_CLAIMED, kinds)
        self.assertIn(EV_TASK_HANDED_OFF, kinds)
        # 创建 → 甲认领 → 甲交接给乙 → 乙认领
        self.assertEqual(
            len(kinds), 4,
            f"交接链不完整:{kinds}",
        )


# ====================================================================
class TestMirror(Base):
    """Agent 本地镜像:先验后存,验不过就拒收并记录异议。"""

    def mirror_for(self, agent_id: str) -> Mirror:
        m = Mirror(self.tmp / f"{agent_id}-mirror.db", agent_id)
        m.set_hub_key(self.hub.public_pem().decode())
        return m

    def test_accepts_genuine_events(self):
        _, a1 = self.make_agent("a1", "甲", ["analyze"])
        self.make_task("活儿", "analyze")
        p = {"op": "claim_next", "agent_id": "a1", "capabilities": ["analyze"]}
        self.store.claim_next("a1", ["analyze"], 30, payload_factory=lambda *_: p,
                              attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, None, p))
        m = self.mirror_for("a1")
        m.upsert_peer_key("a1", a1.public_pem().decode())
        m.upsert_peer_key("hub", self.hub.public_pem().decode())
        raw = [e.to_dict() for e in self.store.get_events(after_seq=-1)]
        report = m.sync(raw)
        self.assertEqual(report["rejected"], [])
        self.assertEqual(report["accepted"], len(raw))
        self.assertTrue(m.verify_local()["ok"])

    def test_rejects_forged_event(self):
        _, a1 = self.make_agent("a1", "甲", ["analyze"])
        t = self.make_task("活儿", "analyze")
        p = {"op": "claim", "task_id": t["task_id"], "agent_id": "a1"}
        self.store.claim_task(t["task_id"], "a1", 30, payload=p,
                              attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, t["task_id"], p))
        m = self.mirror_for("a1")
        m.upsert_peer_key("a1", a1.public_pem().decode())

        ev = self.store.get_events(after_seq=-1)[-1]
        forged = ev.to_dict()
        forged["payload"] = dict(ev.payload, result="我编的")
        report = m.sync([forged])
        self.assertEqual(report["accepted"], 0, "镜像收下了伪造事件")
        self.assertEqual(len(report["rejected"]), 1)
        self.assertEqual(len(m.disputes()), 1, "异议没有被记录下来")

    def test_records_dispute_when_center_signs_agent_work(self):
        """中心用自己的私钥去签一条本该由 Agent 签的事件,镜像必须发现。"""
        _, a1 = self.make_agent("a1", "甲", ["analyze"])
        t = self.make_task("活儿", "analyze")
        p = {"op": "claim", "task_id": t["task_id"], "agent_id": "a1"}
        self.store.claim_task(t["task_id"], "a1", 30, payload=p,
                              attest_sig=self.sign("agent:a1", EV_TASK_CLAIMED, t["task_id"], p))
        m = self.mirror_for("a1")
        m.upsert_peer_key("a1", a1.public_pem().decode())

        ev = self.store.get_events(after_seq=-1)[-1]
        # 中心拿着自己的私钥,重新签一条内容被改过的 Agent 事件
        fake = build_event(
            seq=ev.seq, type=ev.type, actor=ev.actor, hub_signer=self.hub,
            prev_hash=ev.prev_hash, task_id=ev.task_id,
            payload=dict(ev.payload, result="中心代签的内容"), server=ev.server,
            attest_sig=self.hub.sign(
                signed_payload_bytes(ev.actor, ev.type, ev.attest_task_id,
                                     dict(ev.payload, result="中心代签的内容"))
            ),
            attest_task_id=ev.attest_task_id, ts=ev.ts, event_id=ev.event_id,
        )
        report = m.sync([fake.to_dict()])
        self.assertEqual(report["accepted"], 0, "镜像接受了中心代签的 Agent 行为")
        self.assertEqual(len(report["rejected"]), 1)


# ====================================================================
class TestHttpApi(unittest.TestCase):
    """走真实 HTTP,确认协议层(验签/状态码)符合约定。"""

    @classmethod
    def setUpClass(cls):
        import os

        cls.tmp = Path(tempfile.mkdtemp(prefix="agentmesh-http-"))
        # 必须在 import hub 之前设好,并且清掉配置缓存 ——
        # get_settings() 是全局单例,第一个测试类会把它定死,后面全部读到脏值。
        os.environ["MESH_DATA_DIR"] = str(cls.tmp / "data")
        os.environ["MESH_KEYS_DIR"] = str(cls.tmp / "keys")
        reset_settings()

        from agentmesh.hub.app import create_app
        import uvicorn

        cls.port = 8799
        cfg = uvicorn.Config(create_app(), host="127.0.0.1", port=cls.port, log_level="error")
        cls.server = uvicorn.Server(cfg)
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        for _ in range(100):
            try:
                httpx.get(f"http://127.0.0.1:{cls.port}/api/health", timeout=1)
                break
            except Exception:
                time.sleep(0.1)
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=5)
        import os
        os.environ.pop("MESH_DATA_DIR", None)
        os.environ.pop("MESH_KEYS_DIR", None)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_agent_lifecycle_over_http(self):
        tmp = Path(tempfile.mkdtemp())
        signer = load_or_create_signer(tmp / "http-a1.pem")
        pem = signer.public_pem().decode()
        actor = "agent:http-a1"

        reg = {"op": "register", "agent_id": "http-a1", "display_name": "阿一",
               "capabilities": ["analyze"], "key_fingerprint": signer.public_identity()}
        r = httpx.post(f"{self.base}/api/agents/register", json={
            "agent_id": "http-a1", "display_name": "阿一", "role": "", "capabilities": ["analyze"],
            "pubkey_pem": pem, "alg": signer.algorithm, "meta": {}, "payload": reg,
            "attest_sig": signer.sign(signed_payload_bytes(actor, "agent.registered", None, reg)),
        }, timeout=10)
        self.assertEqual(r.status_code, 200, r.text)

        # 签名错误的请求必须被拒
        bad = {"op": "claim_next", "agent_id": "http-a1", "capabilities": ["analyze"]}
        r = httpx.post(f"{self.base}/api/tasks/claim-next", json={
            "agent_id": "http-a1", "capabilities": ["analyze"], "payload": bad,
            "attest_sig": "AAAA",  # 垃圾签名
        }, timeout=10)
        self.assertIn(r.status_code, (401, 403), f"垃圾签名竟然被接受:{r.status_code}")

        # 正确签名可以领活
        httpx.post(f"{self.base}/api/tasks", json={
            "title": "HTTP 冒烟任务", "description": "", "required_capability": "analyze",
            "priority": 5,
        }, timeout=10)
        sig = signer.sign(signed_payload_bytes(actor, EV_TASK_CLAIMED, None, bad))
        r = httpx.post(f"{self.base}/api/tasks/claim-next", json={
            "agent_id": "http-a1", "capabilities": ["analyze"], "payload": bad,
            "attest_sig": sig,
        }, timeout=10)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["claimed"], r.text)
        shutil.rmtree(tmp, ignore_errors=True)

    def test_verify_endpoint_reports_ok(self):
        r = httpx.get(f"{self.base}/api/verify", timeout=20)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["ok"], r.json()["problems"])

    def test_dashboard_is_served(self):
        r = httpx.get(self.base + "/", timeout=10)
        self.assertEqual(r.status_code, 200)
        self.assertIn("AgentMesh", r.text)
        for asset in ("/static/app.js", "/static/style.css"):
            self.assertEqual(httpx.get(self.base + asset, timeout=10).status_code, 200)


# ====================================================================
class TestSecurityPaths(Base):
    """注册令牌与密钥轮换 —— 都是安全边界,必须有回归测试。

    密钥轮换这条曾经 500:重构事件模型时把 store 的参数名从 intent 改成 payload,
    只改了调用点没改定义,单测又没覆盖到这个方法,于是混进了发布版本。
    """

    def test_rotate_agent_key_store_level(self):
        from agentmesh.signing import Ed25519Signer
        from agentmesh.events import EV_AGENT_KEY_ROTATED

        _, old_signer = self.make_agent("rot", "轮换", ["analyze"])
        new_signer = Ed25519Signer.generate()
        payload = {"op": "rotate_key", "agent_id": "rot", "nonce": "abc123"}
        self.store.rotate_agent_key(
            agent_id="rot",
            pubkey_pem=new_signer.public_pem().decode(),
            fingerprint=new_signer.public_identity(),
            alg="ed25519",
            payload=payload,
            # 轮换必须由旧私钥签名:新钥证明不了"我原来是它"
            attest_sig=old_signer.sign(
                signed_payload_bytes("agent:rot", EV_AGENT_KEY_ROTATED, None, payload)
            ),
        )
        self.assertEqual(
            self.store.get_agent("rot")["key_fingerprint"], new_signer.public_identity()
        )
        # 关键:换钥之后,换钥之前用旧钥签的事件必须仍然验得过。
        # 只保留当前公钥的话,审计链会从换钥那一刻起全部判为伪造。
        report = self.verify()
        self.assertTrue(report["ok"], report["problems"])

    def test_new_key_is_pinned_after_rotation(self):
        """换过钥之后,拿旧公钥来注册必须被拒 —— 否则谁都能顶替。"""
        from agentmesh.signing import Ed25519Signer
        from agentmesh.events import EV_AGENT_KEY_ROTATED

        _, old_signer = self.make_agent("rot2", "轮换2", ["analyze"])
        new_signer = Ed25519Signer.generate()
        payload = {"op": "rotate_key", "agent_id": "rot2", "nonce": "n"}
        self.store.rotate_agent_key(
            agent_id="rot2", pubkey_pem=new_signer.public_pem().decode(),
            fingerprint=new_signer.public_identity(), alg="ed25519",
            payload=payload,
            attest_sig=old_signer.sign(
                signed_payload_bytes("agent:rot2", EV_AGENT_KEY_ROTATED, None, payload)
            ),
        )
        # 现在拿【旧私钥】重新注册 —— 公钥与已钉定的不符,必须拒绝
        with self.assertRaises(ConflictError):
            reg = {"op": "register", "agent_id": "rot2", "display_name": "冒充",
                   "capabilities": ["analyze"], "key_fingerprint": old_signer.public_identity()}
            self.store.register_agent(
                agent_id="rot2", display_name="冒充", role="", capabilities=["analyze"],
                pubkey_pem=old_signer.public_pem().decode(),
                key_fingerprint=old_signer.public_identity(), alg="ed25519",
                payload=reg,
                attest_sig=old_signer.sign(
                    signed_payload_bytes("agent:rot2", "agent.registered", None, reg)
                ),
            )


class TestEnrollmentToken(unittest.TestCase):
    """注册口令:设了就得真的拦得住。"""

    @classmethod
    def setUpClass(cls):
        import os

        cls.tmp = Path(tempfile.mkdtemp(prefix="agentmesh-token-"))
        os.environ["MESH_DATA_DIR"] = str(cls.tmp / "data")
        os.environ["MESH_KEYS_DIR"] = str(cls.tmp / "keys")
        os.environ["MESH_ENROLLMENT_TOKEN"] = "tok-abc123"
        reset_settings()

        from agentmesh.hub.app import create_app
        import uvicorn

        cls.port = 8802
        cfg = uvicorn.Config(create_app(), host="127.0.0.1", port=cls.port, log_level="critical")
        cls.server = uvicorn.Server(cfg)
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        for _ in range(100):
            try:
                httpx.get(f"http://127.0.0.1:{cls.port}/api/health", timeout=1)
                break
            except Exception:
                time.sleep(0.1)
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.tmpdir = Path(tempfile.mkdtemp(prefix="agentmesh-token-keys-"))

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=5)
        import os

        for k in ("MESH_DATA_DIR", "MESH_KEYS_DIR", "MESH_ENROLLMENT_TOKEN"):
            os.environ.pop(k, None)
        reset_settings()
        shutil.rmtree(cls.tmp, ignore_errors=True)
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _register(self, agent_id, token):
        s = load_or_create_signer(self.tmpdir / f"{agent_id}.pem")
        pl = {"op": "register", "agent_id": agent_id, "display_name": agent_id,
              "capabilities": ["analyze"], "key_fingerprint": s.public_identity()}
        h = {"X-Enrollment-Token": token} if token is not None else {}
        return httpx.post(f"{self.base}/api/agents/register", json={
            "agent_id": agent_id, "display_name": agent_id, "role": "",
            "capabilities": ["analyze"], "pubkey_pem": s.public_pem().decode(),
            "alg": s.algorithm, "meta": {}, "payload": pl,
            "attest_sig": s.sign(signed_payload_bytes(f"agent:{agent_id}",
                                                     "agent.registered", None, pl)),
        }, headers=h, timeout=10)

    def test_register_requires_token(self):
        self.assertEqual(self._register("ok-agent", "tok-abc123").status_code, 200)
        self.assertIn(self._register("bad-agent", "wrong").status_code, (401, 403))

    def test_admin_endpoints_require_token(self):
        body = {"title": "x", "required_capability": "", "priority": 5}
        self.assertEqual(httpx.post(f"{self.base}/api/tasks", json=body, timeout=10).status_code, 401)
        self.assertEqual(httpx.post(f"{self.base}/api/tasks", json=body,
                                    headers={"X-Operator-Token": "tok-abc123"},
                                    timeout=10).status_code, 200)

    def test_rotate_key_over_http(self):
        """轮换走 HTTP 全流程:旧钥证明 → 换钥 → 旧钥失效。"""
        from agentmesh.signing import Ed25519Signer
        from agentmesh.events import EV_AGENT_KEY_ROTATED

        old = load_or_create_signer(self.tmpdir / "rot-http.pem")
        self._register("rot-http", "tok-abc123")
        # 上面的 _register 用的是同一个 signer 文件,取回来即可
        new = Ed25519Signer.generate()
        pl = {"op": "rotate_key", "agent_id": "rot-http", "nonce": "n1"}
        r = httpx.post(f"{self.base}/api/agents/rot-http/rotate-key", json={
            "agent_id": "rot-http", "pubkey_pem": new.public_pem().decode(),
            "alg": "ed25519", "payload": pl,
            "attest_sig": old.sign(signed_payload_bytes("agent:rot-http",
                                                        EV_AGENT_KEY_ROTATED, None, pl)),
        }, timeout=10)
        self.assertEqual(r.status_code, 200, r.text)

        claim = {"op": "claim_next", "agent_id": "rot-http", "capabilities": ["analyze"]}
        r_old = httpx.post(f"{self.base}/api/tasks/claim-next", json={
            "agent_id": "rot-http", "capabilities": ["analyze"], "payload": claim,
            "attest_sig": old.sign(signed_payload_bytes("agent:rot-http", "task.claimed", None, claim)),
        }, timeout=10)
        self.assertIn(r_old.status_code, (401, 403), "旧私钥换钥后仍能操作,轮换形同虚设")
        r_new = httpx.post(f"{self.base}/api/tasks/claim-next", json={
            "agent_id": "rot-http", "capabilities": ["analyze"], "payload": claim,
            "attest_sig": new.sign(signed_payload_bytes("agent:rot-http", "task.claimed", None, claim)),
        }, timeout=10)
        self.assertEqual(r_new.status_code, 200, r_new.text)

    def test_chain_still_verifies_after_rotation(self):
        v = httpx.get(f"{self.base}/api/verify", timeout=20).json()
        self.assertTrue(v["ok"], v["problems"])


if __name__ == "__main__":
    unittest.main(verbosity=2)