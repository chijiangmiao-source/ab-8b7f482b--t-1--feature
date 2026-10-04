#!/usr/bin/env bash
# 验收入口：代码测试 → 构建检查 → API/HTTP 冒烟；完成后退出，退出码即验收结果。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"
PORT="${VERIFY_PORT:-18080}"

echo "=================================================="
echo " [1/3] 代码测试（合法重传 / 非法等待扩展 / 冻结审计等）"
echo "=================================================="
"$PY" -m unittest discover -s tests -v

echo
echo "=================================================="
echo " [2/3] 构建检查（语法编译 + 模块导入）"
echo "=================================================="
"$PY" -m py_compile app/*.py tests/*.py scripts/smoke.py
"$PY" -c "import app.server, app.t1proto, app.store; print('模块导入检查 OK')"
echo "构建检查 OK"

echo
echo "=================================================="
echo " [3/3] API/HTTP 冒烟（真实服务，端口 $PORT）"
echo "=================================================="
STORE_PATH="" HOST=127.0.0.1 PORT="$PORT" "$PY" -m app.server &
SRV_PID=$!
cleanup() { kill "$SRV_PID" 2>/dev/null || true; wait "$SRV_PID" 2>/dev/null || true; }
trap cleanup EXIT

READY=0
for _ in $(seq 1 50); do
  if "$PY" - "$PORT" <<'EOF' 2>/dev/null
import sys, urllib.request
with urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/health", timeout=1) as r:
    sys.exit(0 if r.status == 200 else 1)
EOF
  then READY=1; break; fi
  sleep 0.2
done
if [ "$READY" != "1" ]; then
  echo "服务未在预期时间内就绪" >&2
  exit 1
fi

BASE_URL="http://127.0.0.1:$PORT" "$PY" scripts/smoke.py

cleanup
trap - EXIT

echo
echo "VERIFY OK：全部验收通过"
exit 0
