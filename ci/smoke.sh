#!/usr/bin/env bash
# End-to-end smoke test: real binary, real Python upstream, curl
# through the gateway, then audit-log assertions. Invoked by CI as
# `bash ci/smoke.sh` after `go build -o /tmp/mcp-gateway-lite`.
set -euo pipefail

BIN=${GW_BIN:-/tmp/mcp-gateway-lite}
STUB_HOST=127.0.0.1
STUB_PORT=3901

CLEANUP_PIDS=()
cleanup() {
  for pid in "${CLEANUP_PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for_url() {
  local url=$1
  for i in $(seq 1 40); do
    if curl -s -o /dev/null "$url"; then return 0; fi
    sleep 0.25
  done
  echo "never came up: $url"
  return 1
}

wait_for_healthz() {
  local url=$1
  for i in $(seq 1 40); do
    if curl -sf "$url" > /dev/null; then return 0; fi
    sleep 0.25
  done
  echo "gateway never came up: $url"
  return 1
}

start_stub() {
  python3 ci/upstream_stub.py "$STUB_HOST" "$STUB_PORT" &
  STUB=$!
  CLEANUP_PIDS+=("$STUB")
  wait_for_url "http://$STUB_HOST:$STUB_PORT/"
}

stop_stub() {
  kill "$STUB" 2>/dev/null || true
  wait "$STUB" 2>/dev/null || true
}

echo "=== basics ==="
"$BIN" --version
"$BIN" --check --config example.config.json

start_stub

echo "=== M1: proxy + audit ==="
"$BIN" --listen 127.0.0.1:8385 --upstream "files=http://$STUB_HOST:$STUB_PORT/mcp" --audit /tmp/audit.jsonl &
GW=$!
CLEANUP_PIDS+=("$GW")
wait_for_healthz http://127.0.0.1:8385/healthz

RESP=$(curl -sf -X POST http://127.0.0.1:8385/mcp/files \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Session-Id: smoke-1' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}')
echo "$RESP"
echo "$RESP" | grep -qF '"jsonrpc"'
curl -sf -X POST http://127.0.0.1:8385/mcp/files \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}' \
  > /dev/null
if curl -sf -X POST http://127.0.0.1:8385/mcp/nope -d '{}' > /dev/null; then
  echo 'expected 404 for unknown upstream'
  exit 1
fi
kill "$GW" && wait "$GW" 2>/dev/null || true
echo '--- audit log ---'
cat /tmp/audit.jsonl
grep -qF '"rpc_methods":["initialize"]' /tmp/audit.jsonl
grep -qF '"tools":["read_file"]' /tmp/audit.jsonl
grep -qF '"session_id":"smoke-1"' /tmp/audit.jsonl
grep -qF 'unknown upstream' /tmp/audit.jsonl
if grep -qF '/etc/hosts' /tmp/audit.jsonl; then
  echo 'FAIL: tool arguments leaked into audit log'
  exit 1
fi

echo "=== M3b: tools/list response filtering ==="
cat > /tmp/filter.config.json <<EOF
{
  "listen": "127.0.0.1:8386",
  "audit": {"path": "/tmp/audit-filter.jsonl"},
  "upstreams": [
    {"name": "files", "url": "http://$STUB_HOST:$STUB_PORT/mcp", "tools_deny": ["delete_file"]}
  ]
}
EOF
"$BIN" --config /tmp/filter.config.json &
GW2=$!
CLEANUP_PIDS+=("$GW2")
wait_for_healthz http://127.0.0.1:8386/healthz

LIST=$(curl -sf -X POST http://127.0.0.1:8386/mcp/files \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":11,"method":"tools/list"}')
echo "$LIST"
echo "$LIST" | grep -qF '"read_file"'
echo "$LIST" | grep -qF '"search"'
if echo "$LIST" | grep -qF 'delete_file'; then
  echo 'FAIL: denied tool visible in filtered tools/list'
  exit 1
fi
# the denied tool is still blocked at call time, and the audit records it
CODE=$(curl -s -o /tmp/blocked.json -w '%{http_code}' -X POST http://127.0.0.1:8386/mcp/files \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"x"}}}')
test "$CODE" = "403"
grep -qF -- '-32003' /tmp/blocked.json
kill "$GW2" && wait "$GW2" 2>/dev/null || true
echo '--- filter audit log ---'
cat /tmp/audit-filter.jsonl
grep -qF '"tools_filtered":1' /tmp/audit-filter.jsonl
grep -qF 'tool blocked by policy: delete_file' /tmp/audit-filter.jsonl

echo "=== M3b: tools_lock init + drift enforcement ==="
rm -f /tmp/gw.lock
"$BIN" --lock-init --lock-file /tmp/gw.lock --upstream "files=http://$STUB_HOST:$STUB_PORT/mcp"
cat /tmp/gw.lock
grep -qF '"toolsHash"' /tmp/gw.lock
grep -qF '"toolsDetail"' /tmp/gw.lock

# capture the clean tools/list straight from the stub for the
# cross-implementation check against real mcp-sentinel below
curl -sf -X POST "http://$STUB_HOST:$STUB_PORT/mcp" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' > /tmp/tools-clean.json

cat > /tmp/lock.config.json <<EOF
{
  "listen": "127.0.0.1:8387",
  "audit": {"path": "/tmp/audit-lock.jsonl"},
  "upstreams": [
    {"name": "files", "url": "http://$STUB_HOST:$STUB_PORT/mcp", "tools_lock": {"file": "/tmp/gw.lock"}}
  ]
}
EOF
"$BIN" --config /tmp/lock.config.json &
GW3=$!
CLEANUP_PIDS+=("$GW3")
wait_for_healthz http://127.0.0.1:8387/healthz

CLEAN=$(curl -sf -X POST http://127.0.0.1:8387/mcp/files \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":21,"method":"tools/list"}')
echo "$CLEAN" | grep -qF '"read_file"'

echo "--- drifting the upstream (rug pull) ---"
stop_stub
STUB_DRIFT=1 python3 ci/upstream_stub.py "$STUB_HOST" "$STUB_PORT" &
STUB=$!
CLEANUP_PIDS+=("$STUB")
wait_for_url "http://$STUB_HOST:$STUB_PORT/"

CODE=$(curl -s -o /tmp/drift.json -w '%{http_code}' -X POST http://127.0.0.1:8387/mcp/files \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":22,"method":"tools/list"}')
cat /tmp/drift.json
test "$CODE" = "403"
grep -qF -- '-32004' /tmp/drift.json
if grep -qF 'attacker.example' /tmp/drift.json; then
  echo 'FAIL: drifted tool description reached the client'
  exit 1
fi
curl -sf -X POST "http://$STUB_HOST:$STUB_PORT/mcp" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' > /tmp/tools-drift.json
kill "$GW3" && wait "$GW3" 2>/dev/null || true
echo '--- lock audit log ---'
cat /tmp/audit-lock.jsonl
grep -qF '"tools_drift":true' /tmp/audit-lock.jsonl

echo "=== cross-check: real mcp-sentinel agrees with the gateway lockfile ==="
git clone --depth 1 https://github.com/bharat3645/mcp-sentinel /tmp/sentinel
python3 - <<'PY'
import json
import sys

sys.path.insert(0, "/tmp/sentinel")
from mcp_sentinel import lockfile as lf

lock = json.load(open("/tmp/gw.lock"))
clean = json.load(open("/tmp/tools-clean.json"))
drifted = json.load(open("/tmp/tools-drift.json"))

# 1. sentinel's tools_hash over the live capture equals the toolsHash
#    the gateway wrote: the two implementations agree byte-for-byte.
h = lf.tools_hash(clean)
locked = lock["servers"]["files"]["toolsHash"]
assert h == locked, (h, locked)
print("sentinel tools_hash matches gateway lockfile:", h)

# 2. sentinel verify_lock sees the same rug-pull the gateway blocked.
entries = {"files": {}}
drifts = lf.verify_lock(entries, lock, {"files": drifted})
kinds = [d.kind for d in drifts]
assert "tools-changed" in kinds, kinds
print("sentinel verify_lock detects the drift:", kinds)

# 3. and the clean capture verifies clean.
drifts = lf.verify_lock(entries, lock, {"files": clean})
assert not drifts, drifts
print("clean capture verifies clean")
PY

echo "ALL SMOKE CHECKS PASSED"
