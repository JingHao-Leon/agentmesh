#!/usr/bin/env bash
# 跑测试:不需要 pytest,标准库 unittest 即可
set -euo pipefail
cd "$(dirname "$0")"

export MESH_DATA_DIR="${TMPDIR:-/tmp}/agentmesh-test-data"
export MESH_KEYS_DIR="${TMPDIR:-/tmp}/agentmesh-test-keys"
rm -rf "$MESH_DATA_DIR" "$MESH_KEYS_DIR"

.venv/bin/python -m unittest discover -s tests -v "$@"