"""离线校验器 —— 整条链的真话在中心之外。

用法:
    python -m agentmesh.tools.verify                       # 用默认路径
    python -m agentmesh.tools.verify --db /path/mesh.db --keys /path/keys/public
    python -m agentmesh.tools.verify --json                # 机器可读,便于接入 CI

它不 import 中心的任何东西,只读 SQLite 文件和公钥目录。中心说自己是清白的,
不算数;这个脚本说 OK 才算数。

退出码:0 = 全部通过,1 = 发现问题,2 = 用法错误。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from ..config import get_settings
from ..events import Event, verify_chain


def load_events(db_path: Path, after_seq: int = -1, limit: int = 1_000_000) -> list[Event]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM events WHERE seq > ? ORDER BY seq ASC LIMIT ?", (after_seq, limit)
        ).fetchall()
    finally:
        conn.close()
    return [Event.from_row(dict(r)) for r in rows]


def load_pubkeys(keys_dir: Path) -> tuple[dict[str, str], str | None]:
    """公钥目录 → {actor: pem}。hub.pem 同时为 system / operator 背书。"""
    actors: dict[str, str] = {}
    hub_pem: str | None = None
    for p in sorted(keys_dir.glob("*.pem")):
        pem = p.read_text()
        if p.stem == "hub":
            hub_pem = pem
            actors["system"] = pem
            actors["operator"] = pem
        else:
            actors[f"agent:{p.stem}"] = pem
    return actors, hub_pem


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(
        prog="python -m agentmesh.tools.verify", description="离线校验 AgentMesh 事件链"
    )
    parser.add_argument("--db", default=str(settings.db_path), help="mesh.db 路径")
    parser.add_argument("--keys", default=str(settings.hub_pubkey), help="公钥目录")
    parser.add_argument("--after-seq", type=int, default=-1)
    parser.add_argument("--limit", type=int, default=1_000_000)
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"✗ 找不到数据库:{db_path}", file=sys.stderr)
        return 2
    keys_dir = Path(args.keys)
    if not keys_dir.exists():
        print(f"✗ 找不到公钥目录:{keys_dir}", file=sys.stderr)
        return 2

    events = load_events(db_path, args.after_seq, args.limit)
    if not events:
        print("链是空的(还没有任何事件)")
        return 0

    actors, hub_pem = load_pubkeys(keys_dir)
    missing = sorted({e.actor for e in events if e.actor.startswith("agent:")} - set(actors))
    report = verify_chain(
        events,
        lambda a: actors.get(a),
        expected_prev_hash=events[0].prev_hash if args.after_seq >= 0 else "0" * 64,
        check_link=True,
        hub_public_pem=hub_pem.encode() if hub_pem else None,
    )

    if args.json:
        print(json.dumps(
            {**report.to_dict(), "db": str(db_path), "keys": str(keys_dir),
             "missing_pubkeys": missing},
            ensure_ascii=False, indent=2,
        ))
        return 0 if report.ok else 1

    head = events[-1]
    print("═" * 68)
    print("AgentMesh 事件链离线校验")
    print("═" * 68)
    print(f"数据库      {db_path}")
    print(f"公钥目录    {keys_dir}({len(actors)} 个身份)")
    print(f"校验范围    seq {events[0].seq} → {head.seq}(共 {report.total} 条)")
    print(f"链头 hash   {head.hash}")
    if missing:
        print(f"⚠ 缺少公钥 {missing} —— 这些行为无法验签,已计入问题")
    print("─" * 68)
    if report.ok:
        print(f"✅ 全部通过:{report.verified}/{report.total} 条事件的哈希链与签名均有效")
        print("   结论:链未被改序、未被删改;所有 Agent 行为均有其私钥背书")
    else:
        print(f"❌ 发现 {len(report.problems)} 处问题(首次断裂在 seq={report.broken_at_seq})")
        for p in report.problems[:20]:
            print(f"   seq {p.get('seq'):>4} [{p['kind']}] {p['detail']}")
        if len(report.problems) > 20:
            print(f"   …… 还有 {len(report.problems) - 20} 处")
    print("═" * 68)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())