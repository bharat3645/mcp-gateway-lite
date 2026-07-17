# mcp-gateway-lite

[![CI](https://github.com/bharat3645/mcp-gateway-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/bharat3645/mcp-gateway-lite/actions/workflows/ci.yml)

Single-binary, stateless reverse proxy for [MCP](https://modelcontextprotocol.io) Streamable HTTP servers, with a JSON Lines audit trail, per-upstream rate limits, per-tool allow/deny policies, and generated RFC 9728 `.well-known` metadata.

Stdlib-only Go. No frameworks, no dependencies, one process in front of your MCP servers that answers the question enterprises keep asking: **"which agent called which tool, when?"**

```
agent/client ──▶ mcp-gateway-lite ──▶ your MCP servers
                     │
                     └──▶ audit.jsonl  (one line per request)
```

## Why

MCP adoption ran ahead of MCP operations. Most deployments today wire agents straight into MCP servers with no audit trail, no choke point, and no place to hang policy. This gateway is the minimal missing piece:

- **Audit every request** — JSON-RPC method, tools/call tool name, session id, status, timing — as append-only JSONL you can ship to any log pipeline.
- **One URL for many servers** — path-based routing (`/mcp/<name>`) turns N server endpoints into one gateway endpoint.
- **Backpressure** — per-upstream token-bucket rate limits with `429` + `Retry-After`, audited so throttled sessions stay attributable.
- **Containment** — per-tool allow/deny lists: block `delete_file` at the gateway even if the upstream serves it, or run an upstream default-deny with an explicit allowlist.
- **`.well-known` for servers that lack it** — generated [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) protected-resource metadata per upstream.
- **Next: deeper policy hooks** — the roadmap wires [mcp-sentinel](https://github.com/bharat3645/mcp-sentinel)-style tool-schema drift verification into the request path.

## Privacy by construction

The audit log records **metadata only**. JSON-RPC `params` and tool `arguments` are never written — only method names, request ids, and `tools/call` tool names. This is enforced by the extraction code (it structurally cannot emit params) and pinned by tests and a CI check that fails if an argument value ever appears in the audit output.

## Quick start

```sh
go install github.com/bharat3645/mcp-gateway-lite/cmd/mcp-gateway-lite@latest

# flags only:
mcp-gateway-lite --upstream files=http://127.0.0.1:3001/mcp --audit audit.jsonl

# or a config file:
mcp-gateway-lite --config example.config.json
```

Then point your MCP client at `http://127.0.0.1:8385/mcp/files` instead of the upstream directly.

```sh
curl -X POST http://127.0.0.1:8385/mcp/files \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Each request produces one audit line:

```json
{"ts":"2026-07-17T08:01:12.408724Z","upstream":"files","remote":"127.0.0.1:52114","http_method":"POST","path":"/mcp/files","session_id":"5f0c...","rpc_methods":["tools/call"],"rpc_ids":["7"],"tools":["read_file"],"status":200,"bytes_in":183,"bytes_out":412,"duration_ms":12.44}
```

## Configuration

```json
{
  "listen": "127.0.0.1:8385",
  "public_base_url": "https://mcp.example.com",
  "audit": { "path": "audit.jsonl" },
  "upstreams": [
    {
      "name": "files",
      "url": "http://127.0.0.1:3001/mcp",
      "rate_limit": { "requests_per_second": 10, "burst": 20 },
      "tools_deny": ["delete_file"],
      "authorization_servers": ["https://auth.example.com"],
      "resource_name": "Files MCP"
    },
    { "name": "search", "url": "http://127.0.0.1:3002/mcp", "header_timeout_seconds": 60 }
  ]
}
```

| Field | Meaning | Default |
|---|---|---|
| `listen` | Bind address | `127.0.0.1:8385` (loopback on purpose) |
| `public_base_url` | External base URL used in generated `.well-known` metadata (set when behind a TLS-terminating proxy) | derived from request `Host`, `http` scheme |
| `audit.path` | JSONL destination; file (append, 0600) or `-`/empty for stdout | stdout |
| `upstreams[].name` | Route segment: `/mcp/<name>` | required |
| `upstreams[].url` | Upstream MCP endpoint (http/https, no query/fragment) | required |
| `upstreams[].header_timeout_seconds` | Max wait for upstream response *headers*. Bodies are unbounded so SSE streams stay open | 30 |
| `upstreams[].rate_limit.requests_per_second` | Sustained token-bucket refill rate (gateway-wide for the upstream) | unlimited |
| `upstreams[].rate_limit.burst` | Bucket capacity — requests served back-to-back before the sustained rate applies | — |
| `upstreams[].tools_allow` | Exhaustive `tools/call` allowlist (default-deny). Mutually exclusive with `tools_deny` | no policy |
| `upstreams[].tools_deny` | `tools/call` blocklist (best-effort) | no policy |
| `upstreams[].authorization_servers` | Advertised in generated RFC 9728 metadata | none |
| `upstreams[].resource_name` | Human-readable name in generated metadata | none |

Unknown config fields are rejected — a typo fails loudly instead of silently disabling an option. Flags `--listen`, `--audit`, and repeatable `--upstream name=url` override/extend the file; `--check` validates and exits.

## Audit entry schema

| Field | Notes |
|---|---|
| `ts` | RFC 3339 nanosecond UTC, request arrival |
| `upstream` | Route name; empty for unknown-route attempts (those are audited too) |
| `remote` | Client address |
| `http_method`, `path` | Inbound request line |
| `session_id` | `Mcp-Session-Id` request header, if present |
| `protocol_version` | `MCP-Protocol-Version` request header, if present |
| `rpc_methods` | JSON-RPC method names (batch → all, in order) |
| `rpc_ids` | Raw JSON-RPC ids (string ids keep quoting; notifications contribute none) |
| `tools` | `params.name` for each `tools/call` — the only params field ever extracted |
| `rpc_batch` | Body was a JSON-RPC batch array |
| `rpc_invalid` | Body wasn't parseable JSON (or exceeded the 1 MiB metadata cap). Request is proxied regardless (unless an allowlist policy applies) |
| `status` | HTTP status returned to the client |
| `sse` | Response was `text/event-stream` |
| `bytes_in`, `bytes_out` | Body sizes (accurate even past the metadata cap) |
| `duration_ms` | Wall-clock duration |
| `error` | Proxy-level failure or policy verdict (`unknown upstream`, `rate limited`, `tool blocked by policy: <name>`, transport errors) |

## Tool policies

Per-upstream `tools_allow` / `tools_deny` (mutually exclusive) are enforced on `tools/call` at the gateway, riding the same body peek the audit log uses. Blocked requests return `403` + JSON-RPC `-32003` naming the tool, and produce a **full audit entry** with the rpc metadata — blocked calls are the entries operators care about most. Batch semantics: one blocked tool rejects the whole request. Non-tool traffic (`initialize`, `tools/list`, notifications, responses) is never affected.

The two modes fail differently, on purpose:

- **`tools_allow` is default-deny:** unparseable bodies and `tools/call` messages without an extractable tool name are blocked — an allowlist that fails open is theater.
- **`tools_deny` is best-effort:** unparseable bodies pass through; it is a guardrail, not a boundary.

Honest limitation: policies block *calls*; they don't filter denied tools out of `tools/list` responses (that needs response rewriting — roadmap). Agents will see a denied tool listed, then get `403` when calling it, with the denial audited.

## Rate limiting

Per-upstream token bucket: `burst` requests go through back-to-back, then `requests_per_second` sustained. Exhaustion returns `429` with a `Retry-After` header and JSON-RPC error `-32002`, and writes an audit entry (`status: 429`, `error: "rate limited"`, session id included so throttled clients stay attributable).

Two deliberate choices, documented honestly:

- The bucket is **gateway-wide per upstream**, not per client. Per-client fairness needs a trustworthy client identity, which plain `RemoteAddr` behind proxies is not; that belongs to the policy-hooks milestone.
- Limited requests are rejected **before the body is read**, so a flood of oversized bodies can't consume gateway bandwidth. The tradeoff: 429 audit entries carry no `rpc_*` fields.

## .well-known metadata

`GET /.well-known/oauth-protected-resource/mcp/<name>` (RFC 9728 path-insertion form) returns generated protected-resource metadata for each upstream: `resource` (the gateway URL clients actually use), `authorization_servers` and `resource_name` from config, and `bearer_methods_supported: ["header"]` — the gateway never accepts tokens in URLs. Set `public_base_url` when running behind TLS termination so `resource` advertises the real external URL.

## Behavior notes

- **SSE / Streamable HTTP:** responses with `Content-Type: text/event-stream` are flushed through immediately (verified by a test that receives the first event while the upstream is still blocked mid-stream). GET listen channels and POST response streams both pass through.
- **Client-to-server response messages** (Streamable HTTP POSTs carrying `result`/`error` with no `method`) are recognized and not flagged invalid.
- **Unknown routes are audited**, not just rejected — probe attempts are exactly what a security log is for.
- **Failure honesty:** an unreachable upstream returns a JSON-RPC `-32001` error with HTTP 502, and the audit entry records the transport error string.
- **Audit failures never break requests:** a failing audit sink is reported once to stderr; traffic keeps flowing.
- `X-Forwarded-For/Host/Proto` are set on upstream requests; `Authorization` and other headers pass through untouched.
- `/healthz` and `.well-known` reads are not audited — the audit log is MCP traffic plus route probes, not liveness noise.

## What's not here (yet)

1. **M3b — drift verification:** inline `mcp-sentinel`-style lockfile verify (tool-schema drift → block — the rug-pull shape), per-session rate keys, `tools/list` response filtering.
2. **Auth:** the gateway forwards credentials and advertises metadata; it does not mint or verify tokens. Put it behind your SSO-terminating proxy.

If you need multi-tenant session stickiness, load balancing, or an admin UI, you want a heavier gateway — this one is a single static binary you can read in an afternoon.

## Development

```sh
go test -race ./...   # httptest end-to-end suite, no network needed
go vet ./...
go build ./cmd/mcp-gateway-lite
```

CI runs gofmt/vet/race tests/build plus an end-to-end smoke: real binary, real Python upstream, curl through the gateway, then asserts the audit log contains the right metadata **and none of the tool arguments**.

## License

MIT
