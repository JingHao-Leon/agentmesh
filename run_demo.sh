#!/usr/bin/env bash
# ============================================================
# AgentMesh 一键演示
#
#   ./run_demo.sh          起中心 + 7 个 Agent + 灌一批任务
#   ./run_demo.sh --reset  先清空 data/keys,从零开始
#   ./stop_demo.sh         全部停掉
#
# 需要先有 .venv(首次运行看 README 的"两条命令装依赖")。
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

PY=".venv/bin/python"
PORT="${MESH_PORT:-8765}"
LOGS="logs"

if [ ! -x "$PY" ]; then
  echo "找不到 $PY —— 先按 README 建好虚拟环境:"
  echo "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

if [ "${1:-}" = "--reset" ]; then
  echo "==> 清空旧数据"
  ./stop_demo.sh >/dev/null 2>&1 || true
  rm -rf data keys "$LOGS"
fi

mkdir -p "$LOGS"
echo "==> 启动中心 :${PORT}"
"$PY" -m agentmesh.hub --port "$PORT" > "$LOGS/hub.log" 2>&1 &
HUB_PID=$!

for _ in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
if ! curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
  echo "✗ 中心没起来,看 $LOGS/hub.log"; tail -20 "$LOGS/hub.log"; exit 1
fi
echo "    中心已就绪,日志 $LOGS/hub.log"

# 一位员工 = 一个进程。能力不同,任务就落到不同的人手上。
start_agent () {   # $1=id  $2=名字  $3=岗位  $4=能力  $5=单步秒数
  "$PY" -m agentmesh.agent --id "$1" --name "$2" --role "$3" \
        --capabilities "$4" --step-seconds "$5" --hub "http://127.0.0.1:${PORT}" \
        > "$LOGS/$1.log" 2>&1 &
  printf '    %-14s %s(%s)\n' "$1" "$2" "$4"
}

echo "==> 启动 7 个 Agent"
start_agent pm-scope       "产品经理 舒岚" "需求受理"   intake    2
start_agent analyst-lumen  "分析师 卢明"   "需求分析"   analyze   3
start_agent architect-nova "架构师 聂远"   "系统设计"   design    3
start_agent builder-tek    "工程师 谭可"   "编码实现"   implement 3
start_agent qa-vera        "测试 韦安"     "测试验证"   test      3
start_agent reviewer-rhea   "评审 荣曦"     "代码评审"   review    3
start_agent writer-lyra    "文档 柳砚"     "文档编写"   docs      2

sleep 2
echo "==> 灌一批演示任务"
"$PY" -m agentmesh.tools.seed --hub "http://127.0.0.1:${PORT}" >/dev/null

cat <<EOF

────────────────────────────────────────────────────────────
  看板    http://127.0.0.1:${PORT}/
  API文档 http://127.0.0.1:${PORT}/docs

  另开一个终端验证链(不需要连中心):
    .venv/bin/python -m agentmesh.tools.verify
    .venv/bin/python -m agentmesh.tools.tamper

  停止:./stop_demo.sh
────────────────────────────────────────────────────────────
EOF

wait $HUB_PID