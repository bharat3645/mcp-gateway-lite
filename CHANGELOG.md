# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `gateway/bench_test.go`: reproducible benchmark comparing a `tools/call` round trip direct-to-upstream vs. through the gateway (minimal config), with measured overhead documented in the README's new Benchmark section.
- README: real request/response transcripts (real compiled binary, real stub upstream, real `curl`) showing `tools/list` filtering, a denied-tool `403`/`-32003`, and rate-limit `429`/`Retry-After` plus the real `audit.jsonl` it produces — previously only described in prose plus one bare audit-log line, and the only place a full transcript existed was `ci/smoke.sh`, not something a reader would see.
- README: a Mermaid diagram of the actual request/response enforcement pipeline (rate limit → policy check on the way in; lock verification → filtering on the way back), next to the existing deployment-topology diagram which didn't show this ordering. Verified against `gateway/gateway.go`'s real control flow (rate-limit check precedes the policy block by line order; the lock-then-filter order is stated directly in a source comment) before drawing it, not assumed.

## [0.4.0] - 2026-07-17

M3b: the response side — tools/list filtering, inline tool-schema
drift verification, per-session rate keys.

### Added

- `tools/list` response filtering: tool policies now shape what
  clients see, not just what they can call. Filtering is id-matched
  (only responses to the request's own tools/list ids are touched),
  byte-preserving for kept tools and sibling fields, and covers both
  `application/json` and `text/event-stream` responses. SSE events
  are emitted as they complete, preserving mid-stream flushing;
  non-candidate events pass byte-verbatim. Allowlist upstreams fail
  closed on unprocessable responses (403/-32003, error events for
  oversized SSE events); deny-list upstreams fail open. Audit entries
  gain `tools_filtered`.
- `tools_lock`: inline verification of `tools/list` responses against
  an mcp-sentinel-format lockfile. `enforce` (default) replaces
  drifted responses with JSON-RPC `-32004` (HTTP 403 for JSON, an
  in-stream error event for SSE); `warn` passes and audits
  (`tools_drift`). Verification runs before policy filtering, against
  the tools as the server sent them. The Go canonicalizer reproduces
  sentinel's Python hashing byte-for-byte, pinned by golden vectors
  generated with the real sentinel code; CI cross-checks a live
  gateway-written lockfile against an actual mcp-sentinel checkout.
- `--lock-init` / `--lock-file`: a minimal MCP client (initialize,
  notifications/initialized, paginated tools/list, JSON or SSE
  responses) that writes or merges a sentinel-format lockfile:
  sentinel's whole-list `toolsHash` plus a per-tool `toolsDetail`
  extension that keeps verification pagination-proof. Foreign server
  records in an existing lockfile are preserved.
- `rate_limit.per_session`: token buckets keyed by `Mcp-Session-Id`
  (empty id shares one bucket), bounded table (4096/upstream) with
  least-recently-seen eviction. Documented honestly as fairness
  between honest clients, not DoS protection.
- Accept-Encoding is stripped from candidate tools/list exchanges so
  the gateway's transport negotiates (and transparently decompresses)
  compression — filtering and drift checks work against gzip-serving
  upstreams.

### Changed

- JSON-RPC error codes: `-32004` for tool-schema drift (alongside
  `-32001` routing, `-32002` rate limiting, `-32003` policy).
- Version constant moved to `gateway.Version` (single source for the
  CLI and the lock-init client).
- The CI smoke test moved from an inline workflow script to
  `ci/smoke.sh` and now covers filtering, lock-init, drift
  enforcement (rug-pull restart), and the mcp-sentinel cross-check.

### Fixed

- `writeJSONError` now JSON-encodes error messages, so
  client-controlled reason text (tool names) cannot produce an
  invalid error body.

## [0.3.0] - 2026-07-17

M3a: tool policies.

### Added

- Per-upstream `tools_allow` / `tools_deny` (mutually exclusive)
  enforced on `tools/call` at the gateway: 403 + JSON-RPC `-32003`
  naming the blocked tool, full audit entry with rpc metadata
  preserved. Batch semantics: one blocked tool rejects the whole
  request. Non-tool traffic is never affected.
- Deliberate failure modes: allowlists are default-deny (unparseable
  bodies and nameless `tools/call` blocked); deny lists are
  best-effort (unparseable bodies pass). Documented, tested.
- `rpcSummary.ToolCalls` counter so allowlist mode detects
  name-extraction gaps instead of failing open.

### Changed

- JSON-RPC error codes: `-32003` for policy blocks (alongside
  `-32001` routing, `-32002` rate limiting).

## [0.2.0] - 2026-07-17

M2: backpressure + discovery.

### Added

- Per-upstream token-bucket rate limiting
  (`rate_limit.requests_per_second` + `burst`): continuous refill,
  429 + JSON-RPC `-32002` + `Retry-After` on exhaustion, audited
  (`status: 429`, `error: "rate limited"`, session id preserved).
  Limited requests are rejected before the body is read so floods
  can't consume gateway bandwidth — documented tradeoff: 429 entries
  carry no `rpc_*` fields.
- Generated RFC 9728 protected-resource metadata per upstream at
  `/.well-known/oauth-protected-resource/mcp/<name>`: `resource`,
  optional `authorization_servers` + `resource_name` from config,
  `bearer_methods_supported: ["header"]`. New `public_base_url`
  config for TLS-terminating deployments (request-Host fallback).

### Changed

- JSON-RPC error code split: `-32001` for routing errors, `-32002`
  for rate limiting.

## [0.1.0] - 2026-07-17

M1: proxy + audit core.

### Added

- Stateless reverse proxy for MCP Streamable HTTP upstreams with
  path-based routing (`/mcp/<name>` and subpaths, query passthrough),
  built on `httputil.ReverseProxy` (`Rewrite` + `SetXForwarded`).
- JSON Lines audit trail: one entry per request with timestamp,
  upstream, remote, HTTP method/path, `Mcp-Session-Id`,
  `MCP-Protocol-Version`, JSON-RPC method names and ids, `tools/call`
  tool names, status, SSE flag, byte counts, duration, and proxy-level
  errors. Params and tool arguments are never logged; the CI smoke
  test fails if an argument value appears in the audit output.
- JSON-RPC metadata extraction: single messages, batches,
  notifications, client-to-server response messages, positional
  params; bodies over 1 MiB are proxied byte-complete and marked
  `rpc_invalid`.
- SSE passthrough with immediate flush (header timeout bounds only the
  response headers, never the stream).
- Unknown-route auditing, JSON-RPC-shaped 404/502 errors, `/healthz`.
- Config: JSON file with unknown-field rejection + validation
  (loopback listen default, upstream name/URL constraints), flag
  overrides, repeatable `--upstream name=url`, `--check`, `--version`.
- Auditor: append-only 0600 file sink or stdout; sink failures are
  reported once to stderr and never fail requests.
- CLI with graceful shutdown (SIGINT/SIGTERM).
- Tests: httptest end-to-end suite (passthrough, privacy, batch, SSE
  mid-stream flush proof, subpath/query/header routing, dead/unknown
  upstream, oversized bodies, auditor concurrency and file semantics,
  config validation, CLI flows). CI: gofmt, vet, race tests, build,
  plus an end-to-end smoke against a real Python upstream.

### Security

- Audit log is metadata-only by construction; the extractor
  structurally cannot emit JSON-RPC params or tool arguments.
- Default listen address is loopback; wider exposure is an explicit
  operator choice.
- Upstream URLs restricted to http/https without query/fragment;
  upstream names restricted to a safe path-segment alphabet.
