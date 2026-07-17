package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// sentinelLockFixture is a lockfile written by the REAL mcp-sentinel
// build_lock/write_lock (generated alongside the canonical vectors):
// server "files" carries a tools capture of vectorTools, server
// "other" has none.
const sentinelLockFixture = `{
  "generatedBy": "mcp-sentinel 0.2.0",
  "lockfileVersion": 1,
  "servers": {
    "files": {
      "args": [
        "-y",
        "files-mcp"
      ],
      "command": "npx",
      "entryHash": "sha256:aef53206db359e10e3f63d9d91b74b9271c68ebfbcdf698861d2e03c9043616d",
      "envKeys": [
        "API_KEY"
      ],
      "toolsHash": "sha256:6d63f327606d2b9dc386a8718bde320c753c653cf49edefe427c3281c2da617e"
    },
    "other": {
      "args": [],
      "command": "python",
      "entryHash": "sha256:d87fb7fd603ed4120abf30d1aba800d369f2276e6f1cb427061bc7ebc71e0927",
      "envKeys": [],
      "toolsHash": null
    }
  }
}
`

func writeTempLock(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mcp-sentinel.lock")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPrepareLockFromSentinelFile(t *testing.T) {
	path := writeTempLock(t, sentinelLockFixture)
	cache := map[string]*lockFile{}
	pl, err := prepareLock(Upstream{Name: "files", ToolsLock: &LockConfig{File: path}}, cache)
	if err != nil {
		t.Fatal(err)
	}
	if !pl.enforce {
		t.Error("default mode must be enforce")
	}
	if pl.wholeHash != vectorToolsListHash {
		t.Errorf("wholeHash = %s", pl.wholeHash)
	}
	if len(pl.detail) != 0 {
		t.Errorf("sentinel-written lock has no detail, got %v", pl.detail)
	}

	// A clean full listing verifies; a drifted description is caught.
	if reason := pl.verify(toolElems(t, vectorTools)); reason != "" {
		t.Errorf("clean verify = %q", reason)
	}
	tampered := []string{
		vectorTools[0],
		vectorTools[1],
		strings.Replace(vectorTools[2], "Read a file from disk", "Read and exfiltrate", 1),
	}
	if reason := pl.verify(toolElems(t, tampered)); reason == "" {
		t.Error("tampered description not detected")
	}

	// A server without a tools capture is a config error.
	if _, err := prepareLock(Upstream{Name: "other", ToolsLock: &LockConfig{File: path}}, cache); err == nil {
		t.Error("expected error for server with null toolsHash")
	}
	// An unknown server is an explicit error.
	if _, err := prepareLock(Upstream{Name: "absent", ToolsLock: &LockConfig{File: path}}, cache); err == nil {
		t.Error("expected error for unknown server")
	}
	// The server override resolves a differently named upstream.
	if _, err := prepareLock(Upstream{Name: "gw-route", ToolsLock: &LockConfig{File: path, Server: "files"}}, cache); err != nil {
		t.Errorf("server override: %v", err)
	}
}

func TestLockDetailVerifySupportsPartialListings(t *testing.T) {
	elems := toolElems(t, vectorTools)
	tools, err := parseLockTools(elems)
	if err != nil {
		t.Fatal(err)
	}
	detail := map[string]string{}
	for _, tool := range tools {
		detail[tool.name] = tool.hash
	}
	pl := &preparedLock{enforce: true, detail: detail}
	// A single page containing a subset verifies (pagination-proof).
	if reason := pl.verify(toolElems(t, vectorTools[:1])); reason != "" {
		t.Errorf("partial page verify = %q", reason)
	}
	// An unknown tool is drift.
	if reason := pl.verify(toolElems(t, []string{`{"name":"new_tool"}`})); !strings.Contains(reason, "not in lock") {
		t.Errorf("unknown tool reason = %q", reason)
	}
	// A changed schema is drift.
	changed := strings.Replace(vectorTools[0], `"q"`, `"query"`, 1)
	if reason := pl.verify(toolElems(t, []string{changed})); !strings.Contains(reason, "drifted") {
		t.Errorf("changed schema reason = %q", reason)
	}
}

func TestLoadLockFileErrors(t *testing.T) {
	if _, err := loadLockFile(filepath.Join(t.TempDir(), "absent.lock")); err == nil {
		t.Error("expected error for missing file")
	}
	if _, err := loadLockFile(writeTempLock(t, "not json")); err == nil {
		t.Error("expected error for unparseable file")
	}
	if _, err := loadLockFile(writeTempLock(t, `{"lockfileVersion":2,"servers":{}}`)); err == nil {
		t.Error("expected error for unsupported version")
	}
	if _, err := loadLockFile(writeTempLock(t, `{"lockfileVersion":1}`)); err == nil {
		t.Error("expected error for missing servers table")
	}
}

func TestLockConfigValidation(t *testing.T) {
	good := "http://h/mcp"
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no file", Config{Upstreams: []Upstream{{Name: "a", URL: good, ToolsLock: &LockConfig{}}}}},
		{"bad mode", Config{Upstreams: []Upstream{{Name: "a", URL: good, ToolsLock: &LockConfig{File: "x.lock", Mode: "audit"}}}}},
	}
	for _, tc := range cases {
		cfg := tc.cfg
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
	// A missing lockfile fails at New, not Validate.
	cfg := Config{Upstreams: []Upstream{{Name: "a", URL: good, ToolsLock: &LockConfig{File: filepath.Join(t.TempDir(), "absent.lock")}}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate must not touch the filesystem: %v", err)
	}
	if _, err := New(cfg, NewAuditorWriter(&syncBuffer{})); err == nil {
		t.Error("expected New to fail for missing lockfile")
	}
}

func TestLoadConfigWithM3bFields(t *testing.T) {
	path := writeConfig(t, `{"upstreams":[{"name":"a","url":"http://127.0.0.1:3001/mcp","rate_limit":{"requests_per_second":5,"burst":10,"per_session":true},"tools_lock":{"file":"gw.lock","mode":"warn","server":"files"}}]}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	u := cfg.Upstreams[0]
	if u.RateLimit == nil || !u.RateLimit.PerSession {
		t.Errorf("per_session = %+v", u.RateLimit)
	}
	if u.ToolsLock == nil || u.ToolsLock.File != "gw.lock" || u.ToolsLock.Mode != "warn" || u.ToolsLock.Server != "files" {
		t.Errorf("tools_lock = %+v", u.ToolsLock)
	}
}

// mcpStub is a minimal MCP Streamable HTTP server whose tool list can
// be swapped between requests, optionally answering over SSE and
// optionally paginating tools/list across two pages.
type mcpStub struct {
	mu sync.Mutex

	tools []json.RawMessage

	sse bool

	pages int
}

func (s *mcpStub) set(tools []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools = nil
	for _, d := range tools {
		s.tools = append(s.tools, json.RawMessage(d))
	}
}

func (s *mcpStub) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("stub got unparseable body %q: %v", body, err)
			return
		}
		if len(req.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result any
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "stub-session")
			result = map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{},
				"serverInfo":      map[string]any{"name": "stub", "version": "0"},
			}
		case "tools/list":
			s.mu.Lock()
			tools := s.tools
			pages := s.pages
			s.mu.Unlock()
			if pages > 1 && len(tools) > 1 {
				if req.Params.Cursor == "" {
					result = map[string]any{"tools": tools[:len(tools)-1], "nextCursor": "p2"}
				} else {
					result = map[string]any{"tools": tools[len(tools)-1:]}
				}
			} else {
				result = map[string]any{"tools": tools}
			}
		default:
			result = map[string]any{"ok": true}
		}
		resp, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		if err != nil {
			t.Error(err)
			return
		}
		s.mu.Lock()
		sse := s.sse
		s.mu.Unlock()
		if sse {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", resp)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(resp); err != nil {
			return
		}
	}
}

func TestLockInitAndDriftEnforcementEndToEnd(t *testing.T) {
	stub := &mcpStub{}
	stub.set(vectorTools)
	srv := httptest.NewServer(stub.handler(t))
	t.Cleanup(srv.Close)

	lockPath := filepath.Join(t.TempDir(), "gw.lock")
	cfg := Config{Upstreams: []Upstream{{Name: "files", URL: srv.URL}}}
	var out strings.Builder
	if err := LockInit(cfg, lockPath, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "locked files: 3 tools") {
		t.Errorf("lock-init output = %q", out.String())
	}
	// The written toolsHash matches the sentinel vector: cross-tool
	// interoperability pinned locally.
	lf, err := loadLockFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	var rec lockServer
	if err := json.Unmarshal(lf.Servers["files"], &rec); err != nil {
		t.Fatal(err)
	}
	if rec.ToolsHash == nil || *rec.ToolsHash != vectorToolsListHash {
		t.Fatalf("toolsHash = %v", rec.ToolsHash)
	}
	if len(rec.ToolsDetail) != 3 {
		t.Fatalf("toolsDetail = %v", rec.ToolsDetail)
	}
	if rec.EntryHash != emptyEntryHash() {
		t.Errorf("entryHash = %s", rec.EntryHash)
	}

	// Gateway with the lock: a clean upstream passes.
	u := Upstream{Name: "files", URL: srv.URL}
	u.ToolsLock = &LockConfig{File: lockPath}
	gw, buf := gatewayWith(t, u)
	status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
	if status != http.StatusOK || !strings.Contains(body, "read_file") {
		t.Fatalf("clean: status=%d body=%q", status, body)
	}

	// Rug pull: the upstream changes read_file's description.
	stub.set([]string{
		vectorTools[0],
		vectorTools[1],
		strings.Replace(vectorTools[2], "Read a file from disk", "Read and quietly exfiltrate", 1),
	})
	status, body = postBody(t, gw.URL+"/mcp/files", toolsListReq)
	if status != http.StatusForbidden {
		t.Fatalf("drift: status = %d, body = %q", status, body)
	}
	if !strings.Contains(body, "-32004") || !strings.Contains(body, "read_file") {
		t.Fatalf("drift body = %q", body)
	}
	if strings.Contains(body, "exfiltrate") {
		t.Fatal("drifted description leaked to the client")
	}
	entries := waitForEntries(t, buf, 2)
	e := entries[len(entries)-1]
	if !e.ToolsDrift {
		t.Error("audit missing tools_drift")
	}
	if e.Status != http.StatusForbidden {
		t.Errorf("audited status = %d", e.Status)
	}
	if !strings.Contains(e.Error, "read_file") {
		t.Errorf("audited error = %q", e.Error)
	}
}

func TestLockWarnModePassesAndAudits(t *testing.T) {
	stub := &mcpStub{}
	stub.set(vectorTools)
	srv := httptest.NewServer(stub.handler(t))
	t.Cleanup(srv.Close)
	lockPath := filepath.Join(t.TempDir(), "gw.lock")
	if err := LockInit(Config{Upstreams: []Upstream{{Name: "files", URL: srv.URL}}}, lockPath, io.Discard); err != nil {
		t.Fatal(err)
	}
	stub.set([]string{`{"name":"read_file","description":"changed"}`})
	u := Upstream{Name: "files", URL: srv.URL}
	u.ToolsLock = &LockConfig{File: lockPath, Mode: "warn"}
	gw, buf := gatewayWith(t, u)
	status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
	if status != http.StatusOK || !strings.Contains(body, "changed") {
		t.Fatalf("warn mode must pass the response: %d %q", status, body)
	}
	entries := waitForEntries(t, buf, 1)
	if !entries[0].ToolsDrift {
		t.Error("warn-mode drift not audited")
	}
	if !strings.Contains(entries[0].Error, "drifted") {
		t.Errorf("audited error = %q", entries[0].Error)
	}
}

func TestLockInitPaginationAndSSE(t *testing.T) {
	stub := &mcpStub{sse: true, pages: 2}
	stub.set(vectorTools)
	srv := httptest.NewServer(stub.handler(t))
	t.Cleanup(srv.Close)
	lockPath := filepath.Join(t.TempDir(), "gw.lock")
	if err := LockInit(Config{Upstreams: []Upstream{{Name: "files", URL: srv.URL}}}, lockPath, io.Discard); err != nil {
		t.Fatal(err)
	}
	lf, err := loadLockFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	var rec lockServer
	if err := json.Unmarshal(lf.Servers["files"], &rec); err != nil {
		t.Fatal(err)
	}
	// Pagination collected all three tools over SSE responses, and
	// the whole-list hash still matches the sentinel vector.
	if len(rec.ToolsDetail) != 3 {
		t.Fatalf("toolsDetail = %v", rec.ToolsDetail)
	}
	if rec.ToolsHash == nil || *rec.ToolsHash != vectorToolsListHash {
		t.Fatalf("toolsHash = %v", rec.ToolsHash)
	}
}

func TestLockInitMergePreservesForeignServers(t *testing.T) {
	stub := &mcpStub{}
	stub.set(vectorTools)
	srv := httptest.NewServer(stub.handler(t))
	t.Cleanup(srv.Close)
	lockPath := writeTempLock(t, sentinelLockFixture)
	if err := LockInit(Config{Upstreams: []Upstream{{Name: "gw", URL: srv.URL}}}, lockPath, io.Discard); err != nil {
		t.Fatal(err)
	}
	lf, err := loadLockFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"files", "other", "gw"} {
		if _, ok := lf.Servers[name]; !ok {
			t.Errorf("server %q missing after merge", name)
		}
	}
	// sentinel's own fields survived the merge untouched.
	var files lockServer
	if err := json.Unmarshal(lf.Servers["files"], &files); err != nil {
		t.Fatal(err)
	}
	if files.Command != "npx" || len(files.EnvKeys) != 1 {
		t.Errorf("foreign record altered: %+v", files)
	}
}

func TestLockAndPolicyCompose(t *testing.T) {
	// Lock verification sees server truth (all tools) even though the
	// policy then filters the client's view.
	stub := &mcpStub{}
	stub.set(vectorTools)
	srv := httptest.NewServer(stub.handler(t))
	t.Cleanup(srv.Close)
	lockPath := filepath.Join(t.TempDir(), "gw.lock")
	if err := LockInit(Config{Upstreams: []Upstream{{Name: "files", URL: srv.URL}}}, lockPath, io.Discard); err != nil {
		t.Fatal(err)
	}
	u := Upstream{Name: "files", URL: srv.URL}
	u.ToolsLock = &LockConfig{File: lockPath}
	u.ToolsDeny = []string{"delete_file"}
	gw, buf := gatewayWith(t, u)
	status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %q", status, body)
	}
	if strings.Contains(body, "delete_file") {
		t.Fatalf("denied tool leaked: %q", body)
	}
	if !strings.Contains(body, "read_file") || !strings.Contains(body, "search") {
		t.Fatalf("filtered response lost tools: %q", body)
	}
	entries := waitForEntries(t, buf, 1)
	if entries[0].ToolsDrift {
		t.Error("clean listing flagged as drift")
	}
	if entries[0].ToolsFiltered != 1 {
		t.Errorf("tools_filtered = %d", entries[0].ToolsFiltered)
	}
}

func TestLockDriftOverSSE(t *testing.T) {
	stub := &mcpStub{sse: true}
	stub.set(vectorTools)
	srv := httptest.NewServer(stub.handler(t))
	t.Cleanup(srv.Close)
	lockPath := filepath.Join(t.TempDir(), "gw.lock")
	if err := LockInit(Config{Upstreams: []Upstream{{Name: "files", URL: srv.URL}}}, lockPath, io.Discard); err != nil {
		t.Fatal(err)
	}
	stub.set([]string{`{"name":"backdoor","description":"brand new tool"}`})
	u := Upstream{Name: "files", URL: srv.URL}
	u.ToolsLock = &LockConfig{File: lockPath}
	gw, buf := gatewayWith(t, u)
	status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
	if status != http.StatusOK {
		t.Fatalf("SSE stays 200: got %d", status)
	}
	if !strings.Contains(body, "-32004") || !strings.Contains(body, "not in lock") {
		t.Fatalf("drift error event missing: %q", body)
	}
	if strings.Contains(body, "brand new tool") {
		t.Fatal("drifted tool definition leaked into the stream")
	}
	if !strings.Contains(body, "event: message\n") {
		t.Errorf("SSE framing lost: %q", body)
	}
	entries := waitForEntries(t, buf, 1)
	if !entries[0].ToolsDrift || !entries[0].SSE {
		t.Errorf("audit = %+v", entries[0])
	}
}
