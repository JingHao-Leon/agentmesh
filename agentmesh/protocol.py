"""Agent <-> Hub 的线协议(pydantic 模型 = 校验 + 自动生成的 OpenAPI 文档)。

所有 Agent 行为类请求都带 payload + attest_sig 两个字段:
  payload     这条事件的内容本体 —— Agent 自己写的内容
  attest_sig  Agent 私钥对 canonical({"actor","type","task_id","payload"}) 的签名

中心补充的事实(租约时间、重试次数…)走 server 字段,不经过这里。
这样"用户看到的内容"始终是被签名的那一份,中心改不了。

中心的处理顺序永远是:先验签 → 再落库。顺序反了就会出现"先信任再验证"。
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# ---- 注册 / 心跳 ----
class RegisterRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=64, examples=["arch-nova"])
    display_name: str = Field(..., max_length=64, examples=["架构师 Nova"])
    role: str = Field("", max_length=64, examples=["后端架构"])
    capabilities: list[str] = Field(default_factory=list, examples=[["backend", "review"]])
    pubkey_pem: str
    alg: str = "ed25519"
    meta: dict[str, Any] = Field(default_factory=dict)
    payload: dict[str, Any]
    attest_sig: str


class HeartbeatRequest(BaseModel):
    agent_id: str
    current_task: str | None = None
    status_detail: str = ""
    # 心跳很频繁,不进事件日志(否则链会被噪声淹没),
    # 只更新 agents 表的 last_seen。要留痕请用 /progress。
    payload: dict[str, Any] | None = None
    attest_sig: str | None = None


# ---- 任务流转 ----
class ClaimRequest(BaseModel):
    agent_id: str
    task_id: str
    payload: dict[str, Any]
    attest_sig: str


class ClaimNextRequest(BaseModel):
    agent_id: str
    capabilities: list[str] = Field(default_factory=list)
    lease_seconds: int | None = Field(None, ge=5, le=3600)
    payload: dict[str, Any]
    attest_sig: str


class ProgressRequest(BaseModel):
    agent_id: str
    task_id: str
    message: str = Field(..., max_length=500)
    pct: int = Field(0, ge=0, le=100)
    payload: dict[str, Any]
    attest_sig: str


class HandoffRequest(BaseModel):
    agent_id: str          # 发起方(必须持有租约)
    task_id: str
    to_agent: str
    next_capability: str = Field("", max_length=64, examples=["design"])
    reason: str = Field(..., max_length=120)
    note: str = Field("", max_length=500)
    context: dict[str, Any] = Field(default_factory=dict)
    payload: dict[str, Any]
    attest_sig: str


class CompleteRequest(BaseModel):
    agent_id: str
    task_id: str
    result: str = Field(..., max_length=4000)
    artifacts: list[str] = Field(default_factory=list)
    payload: dict[str, Any]
    attest_sig: str


class FailRequest(BaseModel):
    agent_id: str
    task_id: str
    error: str = Field(..., max_length=500)
    requeue: bool = True
    payload: dict[str, Any]
    attest_sig: str


class RotateKeyRequest(BaseModel):
    agent_id: str
    pubkey_pem: str
    alg: str = "ed25519"
    payload: dict[str, Any]
    attest_sig: str


# ---- 管理端 ----
class CreateTaskRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field("", max_length=2000)
    required_capability: str = Field("", max_length=64, examples=["backend"])
    priority: int = Field(5, ge=1, le=10)
    context: dict[str, Any] = Field(default_factory=dict)
    due_at: float | None = None
    # 留空 = operator 创建(管理端 token 保护)。
    # 填了 agent_id = 由某个 Agent 自己长出来的新任务,必须带 intent 签名,
    # 中心只能验签放行,不能代签。
    agent_id: str | None = None
    payload: dict[str, Any] | None = None
    attest_sig: str | None = None


class AgentToggleRequest(BaseModel):
    enabled: bool


# ---- 响应 ----
class AckResponse(BaseModel):
    ok: bool = True
    seq: int
    event_id: str
    hash: str


class TaskView(BaseModel):
    task_id: str
    title: str
    description: str = ""
    required_capability: str = ""
    priority: int = 5
    state: str
    owner: str | None = None
    lease_expires_at: float | None = None
    lease_remaining: float | None = None
    preferred_agent: str | None = None
    handoff_open: bool = False
    attempt: int = 0
    failure_count: int = 0
    result: str = ""
    context: dict[str, Any] = Field(default_factory=dict)
    created_by: str = "operator"
    created_at: float
    updated_at: float


class AgentView(BaseModel):
    agent_id: str
    display_name: str
    role: str = ""
    capabilities: list[str] = Field(default_factory=list)
    enabled: bool = True
    online: bool = False
    status: str = "offline"          # idle | busy | offline | disabled
    current_task: str | None = None
    registered_at: float = 0
    last_seen: float = 0
    heartbeat_age: float | None = None
    key_fingerprint: str = ""
    tasks_done: int = 0
    handoffs_given: int = 0
    handoffs_recv: int = 0