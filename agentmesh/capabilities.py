"""Agent 的能力(可插拔的工作单元)。

每个能力函数负责一步真实产出,并回答两个问题:
  1. 这步做完了吗?
  2. 下一步该谁做?

第二个问题是整个系统的核心:能力函数**自己决定交接给谁**(按所需能力找同伴),
中心既不指定目标 Agent,也不知道谁擅长什么 —— 只在必要时做一次原子认领。

把内置的模拟能力换成真实能力(调 LLM、跑构建、跑测试、发 HTTP)时,
只需要替换这个文件里的注册表,运行时、协议、看板全都不用动。
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Any, Callable

# ---- 执行结果 ----
OUTCOME_DONE = "done"
OUTCOME_HANDOFF = "handoff"


@dataclass
class Outcome:
    kind: str                       # done | handoff
    result: str = ""                # 完成时的产出
    artifacts: list[str] = field(default_factory=list)
    next_capability: str = ""       # 下一步所需能力(决定交接给谁)
    reason: str = ""                # 交接理由(会进事件链,所有人可见)
    note: str = ""                  # 交接说明:我做到哪了/你接着做什么
    context: dict[str, Any] = field(default_factory=dict)
    spawn: list[dict[str, Any]] = field(default_factory=list)  # Agent 自己长出的新任务


@dataclass
class Reporter:
    """交给能力函数用的进度回调,内部负责签名与租约。"""

    _emit: Callable[[str, int], None]
    _work_dir: str

    def progress(self, message: str, pct: int) -> None:
        self._emit(message, pct)


# ---- 产出生成的小工具 ----
def _jitter(*parts: str) -> random.Random:
    seed = int(hashlib.sha256("|".join(parts).encode()).hexdigest()[:12], 16)
    return random.Random(seed)


RISKS = [
    "并发写同一份状态,可能出现竞态",
    "外部依赖超时未做退避,雪崩风险",
    "日志级别不统一,线上难以定位",
    "缺少幂等设计,重试会重复扣减",
    "缓存失效策略不清,存在击穿",
]


def _bullets(rng: random.Random, pool: list[str], n: int = 3) -> list[str]:
    return [f"- {pool[i % len(pool)]}" for i in rng.sample(range(len(pool)), min(n, len(pool)))]


# ---- 内置能力实现 ----

def intake(agent: "Any", task: dict, rep: Reporter) -> Outcome:  # noqa: F821
    """需求受理:把一句人话拆成若干条真正的任务,丢回队列等合适的人来领。

    这一步是"去中心化"最有说服力的地方:工作不是中心派下来的,
    而是一个 Agent 根据自己看到的东西,长出了新的任务。中心只验它的签名。
    """
    rng = _jitter(task["task_id"], "intake")
    rep.progress("拆解需求边界", 30)
    want = (task.get("description") or task["title"]).strip()
    steps = [
        {"cap": "analyze", "title": f"[需求] {task['title']} — 需求分析", "p": 8},
        {"cap": "design", "title": f"[需求] {task['title']} — 方案设计", "p": 7},
        {"cap": "test", "title": f"[需求] {task['title']} — 测试与验收", "p": 6},
    ]
    if rng.random() < 0.5:
        steps.insert(1, {"cap": "implement", "title": f"[需求] {task['title']} — 编码实现", "p": 7})
    rep.progress("写入任务池", 80)
    spawned = [
        {
            "title": s["title"],
            "description": f"由 {agent.display_name} 受理 {task['task_id']} 时拆出。原始诉求:{want}",
            "required_capability": s["cap"],
            "priority": s["p"],
            "context": {
                "origin_task": task["task_id"],
                "origin_agent": agent.agent_id,
                "pipeline": "intake → " + " → ".join(s["cap"] for s in steps),
            },
        }
        for s in steps
    ]
    return Outcome(
        kind=OUTCOME_DONE,
        result="\n".join([f"【需求受理】{task['title']}", "", f"已拆出 {len(spawned)} 条任务:"]
                         + [f"- {s['title']} → 需要能力 {s['required_capability']}" for s in spawned]),
        artifacts=[f"intake:{task['task_id']}"],
        spawn=spawned,
        context={"spawned": len(spawned)},
    )


def analyze(agent: "Any", task: dict, rep: Reporter) -> Outcome:  # noqa: F821
    """需求分析:把模糊需求变成可执行的要点和验收标准。"""
    rng = _jitter(task["task_id"], "analyze")
    rep.progress("拆解需求,提取功能点", 25)
    out = [
        f"【需求分析】{task['title']}",
        "",
        "功能要点:",
        *_bullets(rng, [
            "输入参数需要做边界校验,空值与超长都要覆盖",
            "输出结构固定为 {ok, data, err},便于前端统一处理",
            "失败要可定位:带 error_code 而不是裸 message",
            "同一请求重复提交应幂等",
            "分页从 1 开始还是从 0 开始,需与前端对齐",
        ], 4),
        "",
        "风险:",
        *_bullets(rng, RISKS, 2),
        "",
        "验收标准:",
        "- 正常路径返回 200 且 data 非空",
        "- 异常参数返回 4xx 并带明确 error_code",
        "- P95 延迟 < 200ms",
    ]
    rep.progress("整理验收标准", 90)
    return Outcome(
        kind=OUTCOME_HANDOFF,
        result="\n".join(out),
        next_capability="design",
        reason="需求已澄清,需要架构设计",
        note="已完成需求拆解,关键取舍:输出统一 {ok,data,err};优先保证幂等与错误可定位。",
        context={"analysis_done": True, "risk_count": 2},
    )


def design(agent: "Any", task: dict, rep: Reporter) -> Outcome:  # noqa: F821
    """架构设计:接口契约与数据结构。"""
    rng = _jitter(task["task_id"], "design")
    ctx = task.get("context") or {}
    rep.progress("定接口契约", 30)
    out = [
        f"【架构设计】{task['title']}",
        "",
        "接口契约:",
        "POST /api/v1/{res}  →  {ok, data, err}",
        "",
        "核心数据结构:",
        "  Task{id, title, state, owner, lease_expires_at, attempt}",
        "  Event{seq, type, actor, hash, prev_hash, attest_sig}",
        "",
        "关键决策:",
        *_bullets(rng, [
            "租约而非长锁:Agent 崩溃后任务能自动回队列",
            "事件溯源:状态是事件的投影,可重放重建",
            "签名先验后存:不允许先信任再补验证",
            "认领而非指派:并发由数据库条件更新裁决",
            "哈希链 + 归属签名双层,单靠一层都可被绕过",
        ], 3),
        "",
        f"沿用上一步上下文:风险 {ctx.get('risk_count', 0)} 项,已在设计中预留处理位置",
    ]
    rep.progress("校验契约一致性", 85)
    return Outcome(
        kind=OUTCOME_HANDOFF,
        result="\n".join(out),
        next_capability="implement",
        reason="设计已定,交给实现",
        note="接口/数据结构已固定,实现时请勿改动字段名;契约见上一条事件。",
        context={"design_done": True},
    )


def implement(agent: "Any", task: dict, rep: Reporter) -> Outcome:  # noqa: F821
    """实现:产出代码骨架与关键实现说明。"""
    rng = _jitter(task["task_id"], "implement")
    res = "resource"
    rep.progress("生成代码骨架", 20)
    code = f'''
# {task['title']} — 由 {agent.agent_id} 实现

class {res.capitalize()}Service:
    def __init__(self, repo):
        self.repo = repo

    def handle(self, req):
        # 1. 边界校验:先挡掉非法输入,再谈业务
        err = self.repo.validate(req)
        if err:
            return {{"ok": False, "data": None, "err": err}}

        # 2. 幂等:同一个 idempotency_key 只处理一次
        if self.repo.seen(req.idempotency_key):
            return self.repo.cached_result(req.idempotency_key)

        # 3. 业务处理 + 结果回写(失败也要能查到原因)
        result = self.repo.do_work(req)
        self.repo.save(req.idempotency_key, result)
        return {{"ok": True, "data": result, "err": None}}
'''
    rep.progress("补充错误处理与日志", 70)
    out = [
        f"【实现】{task['title']}",
        "",
        "```python" + code + "```",
        "",
        "实现要点:",
        *_bullets(rng, RISKS, 2),
        "- 所有异常路径都返回结构化 err,不抛裸字符串",
    ]
    return Outcome(
        kind=OUTCOME_HANDOFF,
        result="\n".join(out),
        next_capability="test",
        reason="代码已写完,需要验证",
        note="实现在上一条事件里,可直接跑测试。重点测幂等与并发两条路径。",
        context={"implemented": True},
    )


def test(agent: "Any", task: dict, rep: Reporter) -> Outcome:  # noqa: F821
    """测试:把实现跑成可复现的用例与断言。"""
    rng = _jitter(task["task_id"], "test")
    rep.progress("编写用例", 30)
    out = [
        f"【测试】{task['title']}",
        "",
        "用例清单:",
        "- test_happy_path: 正常参数 → 200 且 data 非空",
        "- test_invalid_param: 缺字段 → 400 + error_code=INVALID",
        "- test_idempotent: 同 key 连发两次 → 结果一致,副作用只发生一次",
        "- test_concurrent_claim: 8 个线程抢同一任务 → 有且仅有 1 个 winner",
        "- test_lease_expire: 租约过期不续租 → 任务自动回到 ready",
        "- test_tamper_detect: 改一条事件的 payload → verify 报 invalid_event",
        "",
        "覆盖度:正常路径 + 6 条边界/异常路径",
        f"待重点回归:{rng.choice(['幂等', '并发认领', '租约回收', '篡改检测'])}",
    ]
    rep.progress("跑并发用例", 80)
    return Outcome(
        kind=OUTCOME_HANDOFF,
        result="\n".join(out),
        next_capability="review",
        reason="用例通过,进入评审",
        note="6 条用例均通过;并发认领用例重复跑 20 次结果稳定。",
        context={"tested": True, "cases": 6},
    )


def review(agent: "Any", task: dict, rep: Reporter) -> Outcome:  # noqa: F821
    """评审:挑毛病,给出通过与否的结论。"""
    rng = _jitter(task["task_id"], "review")
    rep.progress("阅读设计与实现", 30)
    issues = _bullets(rng, RISKS, 3)
    out = [
        f"【评审】{task['title']}",
        "",
        "必须修改:",
        *[f"- {i[2:]}" for i in issues[:2]],
        "",
        "建议优化:",
        *[f"- {i[2:]}" for i in issues[2:]],
        "",
        "结论:有条件通过 —— 上面 2 项必改项改完即可合入",
        "评审依据:分析 → 设计 → 实现 → 测试 四步产出均已查阅,证据链完整",
    ]
    rep.progress("出具结论", 90)
    return Outcome(
        kind=OUTCOME_DONE,
        result="\n".join(out),
        artifacts=[f"review:{task['task_id']}"],
        context={"reviewed": True},
    )


def docs(agent: "Any", task: dict, rep: Reporter) -> Outcome:  # noqa: F821
    """文档:把整条链路写成可读的使用说明。"""
    rep.progress("整理链路", 40)
    out = [
        f"【文档】{task['title']}",
        "",
        "使用方式:",
        "1. python -m agentmesh.hub            # 起中心",
        "2. python -m agentmesh.agent --id ...  # 起一个 Agent",
        "3. python -m agentmesh.tools.seed     # 灌一批任务",
        "4. 打开 http://127.0.0.1:8765/        # 看板",
        "",
        "验证方式:",
        "  python -m agentmesh.tools.verify --db data/mesh.db   # 离线校验整条链",
        "",
        "整条流水线的每一步都在事件链上留了签名,可逐条追责。",
    ]
    return Outcome(kind=OUTCOME_DONE, result="\n".join(out), artifacts=[f"doc:{task['task_id']}"])


# ---- 能力注册表 ----
# 想接入真实能力(调大模型 / 跑 CI / 发消息),在这里注册即可,
# Agent 启动时用 --capabilities 声明自己有哪些能力,中心只做过滤,不做分配。
CAPABILITY_REGISTRY: dict[str, Callable[[Any, dict, Reporter], Outcome]] = {
    "intake": intake,
    "analyze": analyze,
    "design": design,
    "implement": implement,
    "test": test,
    "review": review,
    "docs": docs,
}

# 没有匹配能力时的兜底:认真做完,不做无意义的假活
def general(agent: "Any", task: dict, rep: Reporter) -> Outcome:  # noqa: F821
    rep.progress("读取任务上下文", 30)
    desc = (task.get("description") or "").strip()
    out = [
        f"【已处理】{task['title']}",
        "",
        desc or "(任务未附详细说明)",
        "",
        f"处理人:{agent.display_name}({agent.role})",
        "说明:未匹配到专用能力,按通用方式完成并归档。",
    ]
    return Outcome(kind=OUTCOME_DONE, result="\n".join(out), artifacts=[f"note:{task['task_id']}"])


def resolve(capability: str) -> Callable[[Any, dict, Reporter], Outcome]:
    return CAPABILITY_REGISTRY.get((capability or "").lower(), general)