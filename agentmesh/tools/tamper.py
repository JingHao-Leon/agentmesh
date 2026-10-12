"""篡改检测演示:证明"可验证"不是口号。

对日志副本做三种典型攻击,每次都用离线校验器复验:

  攻击 A 改内容      —— 事后把 payload 里的结果改成"已完成"
  攻击 B 改内容并伪造链接 —— 连 hash 一起重算,链看起来完全自洽
                         (这是中心能做的最狠的事:它有中心私钥)
  攻击 C 删掉一条    —— 把失败的任务记录抹掉

结论:攻击 A 被哈希链抓住,攻击 B 被 Agent 的内容签名抓住,攻击 C 被链接断裂抓住。
中心没有 Agent 私钥,所以 B 也伪造不出"某个 Agent 做过某事"。

安全约束:默认只在副本上动手,原始 mesh.db 一个字节都不碰。
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from ..config import get_settings
from ..events import Event, compute_hash, verify_chain
from ..signing import canonical_json, load_or_create_signer
from .verify import load_events, load_pubkeys


def _load_hub_signer(keys_dir: Path):
    """载入中心私钥,用于模拟"中心被完全攻陷"。找不到就返回 None。"""
    hub = Path(keys_dir).parent / "hub"
    if hub.exists():
        try:
            return load_or_create_signer(hub)
        except Exception:
            return None
    return None


def _copy_db(src: Path) -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="agentmesh-tamper-"))
    dst = tmpdir / "mesh.db"
    shutil.copy2(src, dst)
    for suffix in ("-wal", "-shm"):
        side = Path(str(src) + suffix)
        if side.exists():
            shutil.copy2(side, Path(str(dst) + suffix))
    return dst


def _exec(db: Path, sql: str, args: tuple = ()) -> None:
    conn = sqlite3.connect(db)
    try:
        conn.execute(sql, args)
        conn.commit()
    finally:
        conn.close()


def _row(db: Path, seq: int) -> dict:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        r = conn.execute("SELECT * FROM events WHERE seq=?", (seq,)).fetchone()
        return dict(r)
    finally:
        conn.close()


def _rows(db: Path) -> list[dict]:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY seq ASC")]
    finally:
        conn.close()


def _pick_agent_event(db: Path) -> dict | None:
    """挑一条中间位置、由 Agent 发起的事件(归属签名才有意义)。"""
    rows = [r for r in _rows(db) if r["actor"].startswith("agent:")]
    return rows[len(rows) // 2] if rows else None


def _verify(db: Path, keys_dir: Path) -> dict:
    events = load_events(db)
    actors, hub_pem = load_pubkeys(keys_dir)
    rep = verify_chain(
        events, lambda a: actors.get(a), expected_prev_hash="0" * 64,
        check_link=True, hub_public_pem=hub_pem.encode() if hub_pem else None,
    )
    return rep.to_dict()


def _print_result(title: str, report: dict) -> bool:
    status = "✅ 未发现异常" if report["ok"] else f"❌ 被抓住(首个异常 seq={report['broken_at_seq']})"
    print(f"  {title}:{status}")
    for p in report["problems"][:2]:
        print(f"      seq {p.get('seq')} [{p['kind']}] {p['detail'][:96]}")
    return report["ok"]


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(
        prog="python -m agentmesh.tools.tamper",
        description="在日志副本上演示三种篡改攻击,并用离线校验器验证能否发现",
    )
    parser.add_argument("--db", default=str(settings.db_path))
    parser.add_argument("--keys", default=str(settings.hub_pubkey))
    args = parser.parse_args(argv)

    src = Path(args.db)
    keys_dir = Path(args.keys)
    if not src.exists():
        print(f"✗ 找不到数据库:{src};先跑起 hub 和几个 agent 产生一些事件")
        return 2

    baseline = _verify(src, keys_dir)
    print("═" * 70)
    print(f"原始日志校验:{'✅ 通过' if baseline['ok'] else '❌ 已经有问题'}"
          f"(共 {baseline['total']} 条)")
    if not baseline["ok"]:
        _print_result("原始日志", baseline)
        return 1

    target = _pick_agent_event(src)
    if not target:
        print("链里还没有 Agent 发起的事件,先启动几个 agent 再试")
        return 2
    seq = int(target["seq"])
    print(f"选取演示目标:seq={seq} type={target['type']} actor={target['actor']}")
    print("═" * 70)

    caught = []

    # ---- 攻击 A:直接改内容 ----
    print("\n【攻击 A】把这条事件的 payload 改成 '已完成'")
    db = _copy_db(src)
    row = _row(db, seq)
    payload = json.loads(row["payload"] or "{}")
    before = json.dumps(payload, ensure_ascii=False)[:70]
    payload["summary"] = "该任务已成功完成,无异常"
    _exec(db, "UPDATE events SET payload=? WHERE seq=?", (json.dumps(payload, ensure_ascii=False), seq))
    r = _verify(db, keys_dir)
    caught.append(not r["ok"])
    _print_result("校验器", r)

    # ---- 攻击 B:改内容 + 重算 hash + **用中心私钥重新签名**(完全失陷的中心) ----
    print("\n【攻击 B】同上,并把 hash、后续所有 prev_hash 一起重算,")
    print("          再用中心私钥(就在 keys/hub.pem)把整条链重新签一遍")
    print("          —— 这是中心被完全攻陷后能做到的最狠的事")
    db = _copy_db(src)
    hub_signer = _load_hub_signer(keys_dir)
    if hub_signer is None:
        print("          ⚠ 找不到中心私钥,退化为不重签(强度降低)")
        hub_signer = None

    row = _row(db, seq)
    payload = json.loads(row["payload"] or "{}")
    payload["summary"] = "该任务已成功完成,无异常"

    def _rebuild(r: dict, prev: str, p: dict[str, Any]) -> tuple[str, str]:
        """按一条事件重算 hash 与中心签名,返回 (new_hash, new_sig)。"""
        body = {
            "seq": int(r["seq"]),
            "event_id": r["event_id"],
            "ts": float(r["ts"]),
            "type": r["type"],
            "actor": r["actor"],
            "task_id": r["task_id"],
            "payload": p,
            "server": json.loads(r["server"] or "{}"),
            "attest_sig": r["attest_sig"],
            "attest_task_id": r["attest_task_id"],
            "alg": r["alg"],
        }
        h = compute_hash(prev, body)
        s = hub_signer.sign(canonical_json({"prev_hash": prev, **body})) if hub_signer else r["sig"]
        return h, s

    forged_hash, forged_sig = _rebuild(row, row["prev_hash"], payload)
    _exec(
        db,
        "UPDATE events SET payload=?, hash=?, sig=? WHERE seq=?",
        (json.dumps(payload, ensure_ascii=False), forged_hash, forged_sig, seq),
    )
    # 顺着链把后面每一条都重算并重签 —— 链接与中心签名全部恢复自洽
    prev_hash = forged_hash
    for nxt in [r for r in _rows(db) if int(r["seq"]) > seq]:
        nxt_payload = json.loads(nxt["payload"] or "{}")
        new_hash, new_sig = _rebuild(nxt, prev_hash, nxt_payload)
        _exec(
            db,
            "UPDATE events SET prev_hash=?, hash=?, sig=? WHERE seq=?",
            (prev_hash, new_hash, new_sig, int(nxt["seq"])),
        )
        prev_hash = new_hash
    print("          链接与中心签名已全部重算完毕 —— 肉眼和中心自检都看不出异常")
    r = _verify(db, keys_dir)
    caught.append(not r["ok"])
    _print_result("校验器", r)
    if not r["ok"] and r["problems"][0]["kind"] == "invalid_event":
        print("      ↑ 抓它的不是哈希层,也不是中心签名(那些都被重算修好了),")
        print("        而是 Agent 自己的内容签名:中心没有 Agent 私钥,签不出来。")

    # ---- 攻击 C:删一条 ----
    print("\n【攻击 C】删掉中间一条事件(抹掉失败/异常记录)")
    db = _copy_db(src)
    mid = seq + 1
    _exec(db, "DELETE FROM events WHERE seq=?", (mid,))
    r = _verify(db, keys_dir)
    caught.append(not r["ok"])
    _print_result("校验器", r)

    print("\n" + "═" * 70)
    if all(caught):
        print(f"✅ {len(caught)}/{len(caught)} 种攻击全部被检出 —— 可验证,已证实")
        print("═" * 70)
        return 0
    print(f"⚠ 有 {len(caught) - sum(caught)} 种攻击未被发现,这就有问题了")
    print("═" * 70)
    return 1


if __name__ == "__main__":
    sys.exit(main())