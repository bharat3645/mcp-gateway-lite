package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe buffer for audit output in tests.
type syncBuffer struct {
	mu sync.Mutex

	b bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startGateway(t *testing.T, upstreamName, upstreamURL string) (*httptest.Server, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	cfg := Config{Upstreams: []Upstream{{Name: upstreamName, URL: upstreamURL}}}
	gw, err := New(cfg, NewAuditorWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)
	return srv, buf
}

// waitForEntries polls the audit buffer until it holds at least want
// complete entries. The audit entry is written after the response is
// handed to the client, so tests cannot assume it is already there.
func waitForEntries(t *testing.T, buf *syncBuffer, want int) []Entry {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var entries []Entry
		ok := true
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var e Entry
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				ok = false
				break
			}
			entries = append(entries, e)
		}
		if ok && len(entries) >= want {
			return entries
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit log has %d entries, want %d; raw: %q", len(entries), want, buf.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// echoUpstream responds with fixed JSON that reports the request body
// length, so proxy byte-completeness is checkable from the response.
func echoUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"echo_len\":%d}}", len(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProxyPassthrough(t *testing.T) {
	upstream := echoUpstream(t)
	gw, buf := startGateway(t, "files", upstream.URL)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/mcp/files", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", "sess-123")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, got)
	}
	if !strings.Contains(string(got), "\"echo_len\"") {
		t.Fatalf("unexpected body: %s", got)
	}

	entries := waitForEntries(t, buf, 1)
	e := entries[0]
	if e.Upstream != "files" {
		t.Errorf("upstream = %q", e.Upstream)
	}
	if e.HTTPMethod != http.MethodPost {
		t.Errorf("http_method = %q", e.HTTPMethod)
	}
	if len(e.RPCMethods) != 1 || e.RPCMethods[0] != "initialize" {
		t.Errorf("rpc_methods = %v", e.RPCMethods)
	}
	if len(e.RPCIDs) != 1 || e.RPCIDs[0] != "1" {
		t.Errorf("rpc_ids = %v", e.RPCIDs)
	}
	if e.SessionID != "sess-123" {
		t.Errorf("session_id = %q", e.SessionID)
	}
	if e.ProtocolVersion != "2025-06-18" {
		t.Errorf("protocol_version = %q", e.ProtocolVersion)
	}
	if e.Status != http.StatusOK {
		t.Errorf("status = %d", e.Status)
	}
	if e.BytesIn != int64(len(body)) {
		t.Errorf("bytes_in = %d, want %d", e.BytesIn, len(body))
	}
	if e.BytesOut <= 0 {
		t.Errorf("bytes_out = %d", e.BytesOut)
	}
	if e.DurationMS < 0 {
		t.Errorf("duration_ms = %f", e.DurationMS)
	}
	if e.RPCInvalid || e.RPCBatch {
		t.Errorf("unexpected flags in %+v", e)
	}
}

func TestAuditNeverLogsToolArguments(t *testing.T) {
	upstream := echoUpstream(t)
	gw, buf := startGateway(t, "files", upstream.URL)

	const secret = "hunter2-super-secret-value"
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"` + secret + `"}}}`
	resp, err := http.Post(gw.URL+"/mcp/files", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	entries := waitForEntries(t, buf, 1)
	e := entries[0]
	if len(e.Tools) != 1 || e.Tools[0] != "read_file" {
		t.Errorf("tools = %v", e.Tools)
	}
	if len(e.RPCMethods) != 1 || e.RPCMethods[0] != "tools/call" {
		t.Errorf("rpc_methods = %v", e.RPCMethods)
	}
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("audit log leaked tool arguments: %s", buf.String())
	}
}

func TestBatchRequestAudited(t *testing.T) {
	upstream := echoUpstream(t)
	gw, buf := startGateway(t, "files", upstream.URL)

	body := `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`
	resp, err := http.Post(gw.URL+"/mcp/files", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	entries := waitForEntries(t, buf, 1)
	e := entries[0]
	if !e.RPCBatch {
		t.Error("expected rpc_batch")
	}
	if len(e.RPCMethods) != 2 || e.RPCMethods[0] != "ping" || e.RPCMethods[1] != "tools/list" {
		t.Errorf("rpc_methods = %v", e.RPCMethods)
	}
	if len(e.RPCIDs) != 2 || e.RPCIDs[0] != "1" || e.RPCIDs[1] != "2" {
		t.Errorf("rpc_ids = %v", e.RPCIDs)
	}
}

func TestUnknownUpstreamAudited404(t *testing.T) {
	upstream := echoUpstream(t)
	gw, buf := startGateway(t, "files", upstream.URL)

	resp, err := http.Post(gw.URL+"/mcp/nope", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	entries := waitForEntries(t, buf, 1)
	e := entries[0]
	if e.Error != "unknown upstream" {
		t.Errorf("error = %q", e.Error)
	}
	if e.Status != http.StatusNotFound {
		t.Errorf("status = %d", e.Status)
	}
	if e.Upstream != "" {
		t.Errorf("upstream = %q, want empty", e.Upstream)
	}
}

func TestHealthz(t *testing.T) {
	upstream := echoUpstream(t)
	gw, _ := startGateway(t, "files", upstream.URL)

	resp, err := http.Get(gw.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "\"status\":\"ok\"") {
		t.Fatalf("body = %s", body)
	}
}

func TestDeadUpstreamAudited502(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	gw, buf := startGateway(t, "gone", deadURL)
	resp, err := http.Post(gw.URL+"/mcp/gone", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "upstream unavailable") {
		t.Fatalf("body = %s", body)
	}

	entries := waitForEntries(t, buf, 1)
	e := entries[0]
	if e.Error == "" {
		t.Error("expected audit error for dead upstream")
	}
	if e.Status != http.StatusBadGateway {
		t.Errorf("status = %d", e.Status)
	}
	if len(e.RPCMethods) != 1 || e.RPCMethods[0] != "ping" {
		t.Errorf("rpc_methods = %v (metadata should be captured even on failure)", e.RPCMethods)
	}
}

func TestSubpathQueryAndHeaderRouting(t *testing.T) {
	type seen struct {
		path  string
		query string
		auth  string
		xff   string
	}
	ch := make(chan seen, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ch <- seen{path: r.URL.Path, query: r.URL.RawQuery, auth: r.Header.Get("Authorization"), xff: r.Header.Get("X-Forwarded-For")}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(upstream.Close)

	gw, buf := startGateway(t, "files", upstream.URL+"/base")
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/mcp/files/sub/path?x=1", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	s := <-ch
	if s.path != "/base/sub/path" {
		t.Errorf("upstream path = %q", s.path)
	}
	if s.query != "x=1" {
		t.Errorf("upstream query = %q", s.query)
	}
	if s.auth != "Bearer tok" {
		t.Errorf("authorization = %q", s.auth)
	}
	if s.xff == "" {
		t.Error("x-forwarded-for not set")
	}

	entries := waitForEntries(t, buf, 1)
	if entries[0].Status != http.StatusAccepted {
		t.Errorf("audited status = %d", entries[0].Status)
	}
}

func TestSSEStreamsThroughGateway(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream writer is not a flusher")
			return
		}
		fmt.Fprint(w, "data: one\n\n")
		fl.Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
		fmt.Fprint(w, "data: two\n\n")
		fl.Flush()
	}))
	t.Cleanup(upstream.Close)

	gw, buf := startGateway(t, "events", upstream.URL)
	resp, err := http.Get(gw.URL + "/mcp/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	line1, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line1 != "data: one\n" {
		t.Fatalf("first event line = %q", line1)
	}
	// The first event arrived while the upstream was still blocked on
	// release — that can only happen if flushes propagate through the
	// proxy immediately rather than at end of stream.
	close(release)
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rest), "data: two") {
		t.Fatalf("rest = %q", rest)
	}

	entries := waitForEntries(t, buf, 1)
	e := entries[0]
	if !e.SSE {
		t.Error("expected sse=true")
	}
	if e.Status != http.StatusOK {
		t.Errorf("status = %d", e.Status)
	}
	if e.BytesOut <= 0 {
		t.Errorf("bytes_out = %d", e.BytesOut)
	}
}

func TestOversizedBodyStillProxiedByteComplete(t *testing.T) {
	big := strings.Repeat("a", maxRPCPeek+4096)
	upstream := echoUpstream(t)
	gw, buf := startGateway(t, "files", upstream.URL)

	resp, err := http.Post(gw.URL+"/mcp/files", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("\"echo_len\":%d", len(big))
	if !strings.Contains(string(body), want) {
		t.Fatalf("upstream did not receive the full body: %s", body)
	}

	entries := waitForEntries(t, buf, 1)
	e := entries[0]
	if !e.RPCInvalid {
		t.Error("expected rpc_invalid for oversized body")
	}
	if e.BytesIn != int64(len(big)) {
		t.Errorf("bytes_in = %d, want %d", e.BytesIn, len(big))
	}
}

func TestNewRejectsNilAuditor(t *testing.T) {
	cfg := Config{Upstreams: []Upstream{{Name: "a", URL: "http://127.0.0.1:1/mcp"}}}
	if _, err := New(cfg, nil); err == nil {
		t.Fatal("expected error for nil auditor")
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cfg := Config{}
	if _, err := New(cfg, NewAuditorWriter(&syncBuffer{})); err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestJoinPath(t *testing.T) {
	cases := []struct {
		base   string
		suffix string
		want   string
	}{
		{"", "", "/"},
		{"/", "", "/"},
		{"/mcp", "", "/mcp"},
		{"/mcp/", "", "/mcp"},
		{"/mcp", "/sub", "/mcp/sub"},
		{"/mcp/", "/sub", "/mcp/sub"},
		{"", "/sub", "/sub"},
		{"/mcp", "/", "/mcp"},
	}
	for _, tc := range cases {
		if got := joinPath(tc.base, tc.suffix); got != tc.want {
			t.Errorf("joinPath(%q, %q) = %q, want %q", tc.base, tc.suffix, got, tc.want)
		}
	}
}
