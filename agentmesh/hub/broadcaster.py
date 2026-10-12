"""WebSocket 广播中心。

Dashboard 打开 /ws 连上来,之后所有事件实时推给它;漏掉的可以用
{"type":"sync","after_seq":N} 补,补完再进入实时流 —— 断线重连不会丢事件。
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import WebSocket


class Broadcaster:
    def __init__(self) -> None:
        self._clients: dict[WebSocket, asyncio.Queue] = {}

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def connect(self, ws: WebSocket) -> asyncio.Queue:
        await ws.accept()
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._clients[ws] = q
        return q

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.pop(ws, None)

    async def send_to(self, ws: WebSocket, message: dict[str, Any]) -> None:
        q = self._clients.get(ws)
        if q is not None:
            await q.put(message)

    async def broadcast(self, message: dict[str, Any]) -> None:
        payload = json.dumps(message, ensure_ascii=False, default=str)
        dead = []
        for ws, q in list(self._clients.items()):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(ws)  # 慢客户端:断开,让前端重连补齐,不拖垮广播
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)