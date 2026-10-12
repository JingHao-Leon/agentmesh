#!/usr/bin/env bash
# 停掉 run_demo.sh 起的所有中心 / Agent 进程
set -uo pipefail
cd "$(dirname "$0")"

killed=0
for pat in "agentmesh.hub" "agentmesh.agent"; do
  pids=$(pgrep -f "$pat" || true)
  if [ -n "$pids" ]; then
    echo "$pids" | xargs kill 2>/dev/null || true
    killed=$((killed + $(echo "$pids" | wc -l | tr -d ' ')))
  fi
done
echo "已停止 $killed 个进程"