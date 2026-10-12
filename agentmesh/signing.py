"""签名层:Ed25519 真签名,公钥固定(key pinning)。

为什么不用 HMAC:
  HMAC 需要验证方持有密钥,中心就同时成了"记账人"和"裁判",去中心化无从谈起。
  Ed25519 下,中心只持有各 Agent 的公钥,只有 Agent 自己能产生有效事件;
  任何人拿到公钥文件都能离线验证整条链。

降级: 若 cryptography 不可用,退化为 HMAC-SHA256(算法名会写进事件里,
验证时会按事件记录的算法走,不会出现"用 A 验 B"的静默错误)。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Protocol

ALG_ED25519 = "ed25519"
ALG_HMAC = "hmac-sha256"


def canonical_json(obj: object) -> bytes:
    """哈希与签名统一使用的确定性序列化。

    sort_keys 保证键序无关,ensure_ascii=False 保留中文原文,
    separators 去掉多余空格 —— 同一逻辑内容在任何机器上都得到同一字节串。
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


class Signer(Protocol):
    algorithm: str

    def sign(self, payload: bytes) -> str: ...

    def public_identity(self) -> str: ...


class Ed25519Signer:
    algorithm = ALG_ED25519

    def __init__(self, private_key) -> None:
        self._key = private_key

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes) -> "Ed25519Signer":
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_private_key(pem, password=None)
        return cls(key)

    @classmethod
    def from_private_file(cls, path: Path) -> "Ed25519Signer":
        return cls.from_pem(Path(path).read_bytes())

    @classmethod
    def from_public_pem(cls, pem: bytes) -> str:
        """从公钥 PEM 取出指纹。只做校验,不生成任何密钥。"""
        from cryptography.hazmat.primitives import serialization

        serialization.load_pem_public_key(pem)  # 不合法会直接抛,用于拒绝垃圾输入
        return fingerprint(pem)

    def private_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization as ser

        return self._key.private_bytes(
            encoding=ser.Encoding.PEM,
            format=ser.PrivateFormat.PKCS8,
            encryption_algorithm=ser.NoEncryption(),
        )

    def public_pem(self) -> bytes:
        from cryptography.hazmat.primitives import serialization as ser

        return self._key.public_key().public_bytes(
            encoding=ser.Encoding.PEM,
            format=ser.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, payload: bytes) -> str:
        return b64e(self._key.sign(payload))

    def public_identity(self) -> str:
        """公钥指纹(SHA-256 前 16 hex),面板上用它肉眼核对"还是同一把钥匙"。"""
        return fingerprint(self.public_pem())


class HmacSigner:
    """降级方案:需要预共享密钥,只在没有 cryptography 的环境用。"""

    algorithm = ALG_HMAC

    def __init__(self, secret: bytes) -> None:
        self._secret = secret

    def sign(self, payload: bytes) -> str:
        return b64e(hmac.new(self._secret, payload, hashlib.sha256).digest())

    def public_identity(self) -> str:
        return "hmac-shared-secret"


def fingerprint(public_pem: bytes | str) -> str:
    raw = public_pem.encode() if isinstance(public_pem, str) else public_pem
    return hashlib.sha256(raw).hexdigest()[:16]


def verify_signature(
    algorithm: str,
    public_pem: bytes,
    payload: bytes,
    signature_b64: str,
) -> tuple[bool, str]:
    """按事件里记录的算法验证签名。返回 (是否通过, 失败原因)。

    public_pem 接受 bytes 或 str(PEM 文本直接读文件时就是 str,别让调用方
    在边界上反复踩这个坑 —— 踩一次表现为"验签失败",极具误导性)。
    """
    if isinstance(public_pem, str):
        public_pem = public_pem.encode()
    try:
        if algorithm == ALG_ED25519:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import serialization

            key = serialization.load_pem_public_key(public_pem)
            try:
                key.verify(b64d(signature_b64), payload)
                return True, "ok"
            except InvalidSignature:
                return False, "签名与公钥不匹配"

        if algorithm == ALG_HMAC:
            secret, identity = public_pem, ""
            expect = b64e(hmac.new(secret, payload, hashlib.sha256).digest())
            if hmac.compare_digest(expect, signature_b64):
                return True, "ok"
            return False, "HMAC 不匹配"

        return False, f"未知算法 {algorithm!r}"
    except Exception as exc:  # 坏 PEM / 坏 base64 一律按验签失败处理,不能静默放行
        return False, f"验签异常:{type(exc).__name__}: {exc}"


def load_or_create_signer(priv_path: Path) -> Ed25519Signer | HmacSigner:
    """读取已有私钥;没有就生成。权限一律 0600,私钥不外传。"""
    priv_path = Path(priv_path)
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    if priv_path.exists():
        return Ed25519Signer.from_private_file(priv_path)
    try:
        signer = Ed25519Signer.generate()
        pem = signer.private_pem()
    except ImportError:
        signer = HmacSigner(secrets.token_bytes(32))
        pem = signer.sign(b"mesh-hmac-key")  # 派生确定性密钥,便于持久化
    fd = os.open(str(priv_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return signer


def write_public_key(public_dir: Path, name: str, pem: bytes) -> str:
    """把公钥落到公钥目录,返回指纹。公钥可以公开。"""
    public_dir = Path(public_dir)
    public_dir.mkdir(parents=True, exist_ok=True)
    target = public_dir / f"{name}.pem"
    target.write_bytes(pem)
    try:
        os.chmod(target, 0o644)
    except OSError:
        pass
    return fingerprint(pem)