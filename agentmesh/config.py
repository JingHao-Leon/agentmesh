"""集中配置。所有可调项都能用环境变量覆盖,方便上云时容器化。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class Settings:
    # ---- 路径 ----
    data_dir: Path = field(
        default_factory=lambda: Path(_env("MESH_DATA_DIR", str(BASE_DIR / "data"))).resolve()
    )
    keys_dir: Path = field(
        default_factory=lambda: Path(_env("MESH_KEYS_DIR", str(BASE_DIR / "keys"))).resolve()
    )

    # ---- Hub ----
    host: str = field(default_factory=lambda: _env("MESH_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("MESH_PORT", 8765))
    # 允许的 Agent 来源,逗号分隔;生产建议改成真实网段
    cors_origins: str = field(default_factory=lambda: _env("MESH_CORS_ORIGINS", "*"))

    # ---- 租约与心跳 ----
    # 租约:Agent 领到任务后必须在此时间内续租,否则任务自动回到队列
    lease_seconds: int = field(default_factory=lambda: _env_int("MESH_LEASE_SECONDS", 30))
    heartbeat_seconds: int = field(default_factory=lambda: _env_int("MESH_HEARTBEAT_SECONDS", 5))
    # 超过该时间没有心跳,Agent 在面板上标记为离线
    offline_after_seconds: int = field(default_factory=lambda: _env_int("MESH_OFFLINE_AFTER", 20))
    # 交接后,目标 Agent 的优先认领窗口;窗口过后任何 Agent 都可抢
    handoff_priority_seconds: int = field(
        default_factory=lambda: _env_int("MESH_HANDOFF_PRIORITY_SECONDS", 25)
    )

    # ---- 安全 ----
    # 中心注册 Agent 公钥时用的登记口令。留空表示不校验(仅限本地演示)
    enrollment_token: str = field(default_factory=lambda: _env("MESH_ENROLLMENT_TOKEN", ""))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "mesh.db"

    @property
    def hub_pubkey(self) -> Path:
        """中心的公钥目录(不公开中心私钥)。"""
        return self.keys_dir / "public"

    @property
    def hub_privkey(self) -> Path:
        return self.keys_dir / "hub"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        (self.keys_dir / "public").mkdir(parents=True, exist_ok=True)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
        _settings.ensure_dirs()
    return _settings


def reset_settings() -> None:
    """清掉缓存,让下次 get_settings() 重新读环境变量。

    测试里多个用例类要切换 MESH_DATA_DIR / MESH_ENROLLMENT_TOKEN,
    不清缓存的话第一个类把配置定死,后面全部读到脏值 —— 踩过一次。
    """
    global _settings
    _settings = None