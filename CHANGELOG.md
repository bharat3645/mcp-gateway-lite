# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
