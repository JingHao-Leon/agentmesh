"""请求鉴权与归属校验。

两件不同的事,别混淆:
  1. 请求鉴权 —— "这个 HTTP 请求是谁发的?"  用 X-Operator-Token(管理端)或
     内容签名(Agent 端)。
  2. 归属校验 —— "链上这条事件真的出自该 Agent?"  写入时验一次,校验链时再验一次。

Agent 端不靠 token,靠私钥:它把事件内容用自己的私钥签名一起发上来,
中心用花名册里的公钥验。验不过就直接 403,绝不"先收下再说"。
"""

from __future__ import annotations

import hmac
from typing import Any

from .events import signed_payload_bytes
from .signing import verify_signature


class AuthError(Exception):
    def __init__(self, message: str, status: int = 403) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def verify_agent_signature(
    public_key_for: Any,
    *,
    actor: str,
    type: str,
    task_id: str | None,
    payload: dict[str, Any],
    attest_sig: str,
) -> None:
    """校验 Agent 对事件内容的签名。不通过就抛 AuthError。"""
    pem = public_key_for(actor)
    if pem is None:
        raise AuthError(f"{actor} 尚未注册,先调 POST /api/agents/register")
    # ⚠ 只认当前密钥。历史密钥仅用于"验过去的记录"，
    # 不能用来授权新动作 —— 否则密钥轮换形同虚设:泄露的旧钥仍能继续操作。
    raw = pem.encode() if isinstance(pem, str) else pem
    data = signed_payload_bytes(actor, type, task_id, payload)
    ok, reason = verify_signature("ed25519", raw, data, attest_sig)
    if not ok:
        raise AuthError(
            f"内容签名校验失败:{reason}(该行为不是 {actor} 用当前密钥做的;"
            "若刚轮换过密钥,请重启 Agent 进程加载新私钥)"
        )


def verify_with_public_key(
    public_pem: str | bytes, *, actor: str, type: str, task_id: str | None,
    payload: dict[str, Any], attest_sig: str,
) -> None:
    """用请求里自带/指定的公钥验签(注册、轮换密钥时用)。"""
    raw = public_pem.encode() if isinstance(public_pem, str) else public_pem
    ok, reason = verify_signature(
        "ed25519", raw, signed_payload_bytes(actor, type, task_id, payload), attest_sig
    )
    if not ok:
        raise AuthError(f"内容签名校验失败:{reason}")


def check_operator_token(provided: str | None, expected: str) -> None:
    """管理端 token 校验。expected 为空 = 本地演示模式,不校验(会打警告)。"""
    if not expected:
        return
    if not provided or not hmac.compare_digest(provided, expected):
        raise AuthError("X-Operator-Token 不正确或缺失", status=401)