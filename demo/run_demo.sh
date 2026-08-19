#!/usr/bin/env bash
# Real, runnable demo: the rug-pull containment story from the README's
# "Tool-schema locking" section, driven end-to-end against the real
# compiled binary and the real ci/upstream_stub.py — nothing simulated.
#
# 1. review + lock a clean tools/list
# 2. gateway enforces the lock; a clean upstream passes through untouched
# 3. the upstream silently rewrites read_file's description (the
#    postmark-mcp attack shape: N clean versions, then a mutated tool
#    description that is itself prompt input to the calling agent)
# 4. the gateway's tools_lock catches the drift inline and blocks the
#    response before the poisoned description ever reaches the client
# 5. a denied tool (delete_file) is blocked at call time too, and the
#    audit log proves call arguments are never recorded, even for the
#    blocked call
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=/tmp/mcp-gateway-lite-demo
STUB_HOST=127.0.0.1
STUB_PORT=3999
GW_ADDR=127.0.0.1:8399
LOCK_FILE=/tmp/demo-gw.lock
AUDIT_FILE=/tmp/demo-audit.jsonl
CONFIG_FILE=/tmp/demo-gw.config.json

CLEANUP_PIDS=()
cleanup() {
  for pid in "${CLEANUP_PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for() {
  for i in $(seq 1 40); do
    if curl -s -o /dev/null "$1"; then return 0; fi
    sleep 0.25
  done
  echo "never came up: $1"; exit 1
}

rm -f "$LOCK_FILE" "$AUDIT_FILE"
go build -o "$BIN" ./cmd/mcp-gateway-lite

echo "=== 1. upstream comes up clean (real MCP tools/list: read_file, delete_file, search) ==="
python3 ci/upstream_stub.py "$STUB_HOST" "$STUB_PORT" &
STUB=$!; CLEANUP_PIDS+=("$STUB")
wait_for "http://$STUB_HOST:$STUB_PORT/"

echo
echo "=== 2. review + lock what we saw (mcp-sentinel-compatible lockfile) ==="
"$BIN" --lock-init --lock-file "$LOCK_FILE" --upstream "files=http://$STUB_HOST:$STUB_PORT/mcp"
cat "$LOCK_FILE"

cat > "$CONFIG_FILE" <<EOF
{
  "listen": "$GW_ADDR",
  "audit": {"path": "$AUDIT_FILE"},
  "upstreams": [
    {"name": "files", "url": "http://$STUB_HOST:$STUB_PORT/mcp", "tools_deny": ["delete_file"], "tools_lock": {"file": "$LOCK_FILE"}}
  ]
}
EOF

echo
echo "=== 3. gateway up, enforcing the lock + the deny policy ==="
"$BIN" --config "$CONFIG_FILE" &
GW=$!; CLEANUP_PIDS+=("$GW")
wait_for "http://$GW_ADDR/healthz"

echo
echo "--- tools/list through the gateway (clean upstream, matches the lock) ---"
curl -sf -X POST "http://$GW_ADDR/mcp/files" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
echo

echo
echo "=== 4. the upstream silently mutates read_file's description (the rug-pull) ==="
kill "$STUB" && wait "$STUB" 2>/dev/null || true
STUB_DRIFT=1 python3 ci/upstream_stub.py "$STUB_HOST" "$STUB_PORT" &
STUB=$!; CLEANUP_PIDS[0]=$STUB
wait_for "http://$STUB_HOST:$STUB_PORT/"

echo "--- what the upstream now actually sends (never reaches the client) ---"
curl -sf -X POST "http://$STUB_HOST:$STUB_PORT/mcp" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
echo

echo
echo "--- same tools/list through the gateway: caught and blocked, not silently passed ---"
DRIFT_CODE=$(curl -s -o /tmp/demo-drift.json -w '%{http_code}' -X POST "http://$GW_ADDR/mcp/files" \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
cat /tmp/demo-drift.json
echo
echo "HTTP status: $DRIFT_CODE"
test "$DRIFT_CODE" = "403"
grep -qF -- '-32004' /tmp/demo-drift.json
if grep -qF 'attacker.example' /tmp/demo-drift.json; then
  echo 'FAIL: poisoned description reached the client'; exit 1
fi
echo "OK: poisoned description never reached the client"

echo
echo "=== 5. delete_file is denied at call time too (never even listed above) ==="
DENY_CODE=$(curl -s -o /tmp/demo-deny.json -w '%{http_code}' -X POST "http://$GW_ADDR/mcp/files" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/etc/shadow"}}}')
cat /tmp/demo-deny.json
echo
test "$DENY_CODE" = "403"
grep -qF -- '-32003' /tmp/demo-deny.json

kill "$GW" && wait "$GW" 2>/dev/null || true

echo
echo "=== 6. the privacy invariant: audit log has both events, arguments never leaked ==="
cat "$AUDIT_FILE"
grep -qF '"tools_drift":true' "$AUDIT_FILE"
grep -qF 'tool blocked by policy: delete_file' "$AUDIT_FILE"
LEAK_COUNT=$(grep -c '/etc/shadow' "$AUDIT_FILE" || true)
echo "occurrences of the blocked call's argument value in the audit log: $LEAK_COUNT"
test "$LEAK_COUNT" = "0"

echo
echo "SMOKE OK: rug-pull caught inline, denied tool blocked, arguments never audited"
