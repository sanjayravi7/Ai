#!/usr/bin/env bash
# Reproducible verification for VULNOVA.
#
#   ./verify_all.sh
#
# Exits non-zero if any stage fails. The render check is a DOM shim, not a browser.
set -uo pipefail
cd "$(dirname "$0")"

PY=.venv/bin/python
PORT="${VULNOVA_PORT:-8123}"
FAILED=0

echo "== 1/3 pytest =="
"$PY" -m pytest tests -q || FAILED=1

echo
echo "== 2/3 product verification =="
"$PY" tools/verify_product.py --db build/vulnova.db || FAILED=1

echo
echo "== 3/3 UI render check (DOM shim — NOT a screenshot) =="
"$PY" -m vulnova.web --db build/vulnova.db --host 127.0.0.1 --port "$PORT" \
    > /tmp/vulnova_verify_server.log 2>&1 &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; }
trap cleanup EXIT

READY=0
for _ in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.5
done
if [ "$READY" -eq 1 ]; then
    node tools/ui_render_check.js --base "http://127.0.0.1:$PORT" || FAILED=1
else
    echo "  [FAIL] server did not start; see /tmp/vulnova_verify_server.log"
    FAILED=1
fi

cleanup
trap - EXIT

echo
if [ "$FAILED" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "CHECKS FAILED"
fi
exit "$FAILED"
