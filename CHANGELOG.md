# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
