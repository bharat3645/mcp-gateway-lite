package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBlockReason(t *testing.T) {
	allowPolicy := newToolPolicy(Upstream{ToolsAllow: []string{"read_file", "search"}})
	denyPolicy := newToolPolicy(Upstream{ToolsDeny: []string{"delete_file"}})

	cases := []struct {
		name    string
		policy  *toolPolicy
		sum     rpcSummary
		blocked bool
	}{
		{"nil policy passes anything", nil, rpcSummary{Tools: []string{"x"}, ToolCalls: 1}, false},
		{"deny miss", denyPolicy, rpcSummary{Tools: []string{"read_file"}, ToolCalls: 1}, false},
		{"deny hit", denyPolicy, rpcSummary{Tools: []string{"delete_file"}, ToolCalls: 1}, true},
		{"deny ignores non-tool traffic", denyPolicy, rpcSummary{Methods: []string{"initialize"}}, false},
		{"deny passes unparseable", denyPolicy, rpcSummary{Invalid: true}, false},
		{"allow hit", allowPolicy, rpcSummary{Tools: []string{"read_file"}, ToolCalls: 1}, false},
		{"allow miss", allowPolicy, rpcSummary{Tools: []string{"write_file"}, ToolCalls: 1}, true},
		{"allow ignores non-tool traffic", allowPolicy, rpcSummary{Methods: []string{"tools/list"}}, false},
		{"allow blocks unparseable", allowPolicy, rpcSummary{Invalid: true}, true},
		{"allow blocks nameless tools/call", allowPolicy, rpcSummary{Methods: []string{"tools/call"}, ToolCalls: 1}, true},
		{"allow batch with one bad tool", allowPolicy, rpcSummary{Tools: []string{"read_file", "rm_rf"}, ToolCalls: 2, Batch: true}, true},
	}
	for _, tc := range cases {
		reason := tc.policy.blockReason(tc.sum)
		if got := reason != ""; got != tc.blocked {
			t.Errorf("%s: blocked = %v (reason %q), want %v", tc.name, got, reason, tc.blocked)
		}
	}
}

func TestDenyPolicyEndToEnd(t *testing.T) {
	upstream := echoUpstream(t)
	buf := &syncBuffer{}
	u := Upstream{Name: "files", URL: upstream.URL}
	u.ToolsDeny = []string{"delete_file"}
	gw, err := New(Config{Upstreams: []Upstream{u}}, NewAuditorWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/mcp/files", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"a.txt"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed tool: status = %d", resp.StatusCode)
	}

	resp, err = http.Post(srv.URL+"/mcp/files", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"a.txt"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied tool: status = %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "-32003") || !strings.Contains(string(body), "delete_file") {
		t.Fatalf("403 body = %s", body)
	}

	entries := waitForEntries(t, buf, 2)
	e := entries[len(entries)-1]
	if e.Status != http.StatusForbidden {
		t.Errorf("audited status = %d", e.Status)
	}
	if !strings.Contains(e.Error, "delete_file") {
		t.Errorf("audited error = %q, want the tool named", e.Error)
	}
	if len(e.Tools) != 1 || e.Tools[0] != "delete_file" {
		t.Errorf("audited tools = %v (blocked calls must keep rpc metadata)", e.Tools)
	}
	if !strings.Contains(buf.String(), `"rpc_methods":["tools/call"]`) {
		t.Error("audited rpc_methods missing on blocked call")
	}
}

func TestAllowPolicyEndToEnd(t *testing.T) {
	upstream := echoUpstream(t)
	buf := &syncBuffer{}
	u := Upstream{Name: "files", URL: upstream.URL}
	u.ToolsAllow = []string{"read_file"}
	gw, err := New(Config{Upstreams: []Upstream{u}}, NewAuditorWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)

	post := func(body string) int {
		t.Helper()
		resp, err := http.Post(srv.URL+"/mcp/files", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if got := post(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`); got != http.StatusOK {
		t.Errorf("allowlisted tool: status = %d", got)
	}
	if got := post(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file"}}`); got != http.StatusForbidden {
		t.Errorf("unlisted tool: status = %d, want 403", got)
	}
	if got := post(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`); got != http.StatusOK {
		t.Errorf("non-tool method: status = %d (policies must not touch it)", got)
	}
	if got := post(`not json at all`); got != http.StatusForbidden {
		t.Errorf("unparseable body in allow mode: status = %d, want 403 (default-deny)", got)
	}
	if got := post(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{}}`); got != http.StatusForbidden {
		t.Errorf("nameless tools/call in allow mode: status = %d, want 403", got)
	}
	if got := post(`[{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file"}},{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"rm_rf"}}]`); got != http.StatusForbidden {
		t.Errorf("batch with unlisted tool: status = %d, want 403 (whole batch rejected)", got)
	}
}

func TestDenyPolicyUnparseableBodyProxied(t *testing.T) {
	upstream := echoUpstream(t)
	buf := &syncBuffer{}
	u := Upstream{Name: "files", URL: upstream.URL}
	u.ToolsDeny = []string{"delete_file"}
	gw, err := New(Config{Upstreams: []Upstream{u}}, NewAuditorWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/mcp/files", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deny mode must proxy unparseable bodies, status = %d", resp.StatusCode)
	}
}

func TestPolicyConfigValidation(t *testing.T) {
	good := "http://h/mcp"
	cases := []struct {
		name string
		cfg  Config
	}{
		{"both allow and deny", Config{Upstreams: []Upstream{{Name: "a", URL: good, ToolsAllow: []string{"x"}, ToolsDeny: []string{"y"}}}}},
		{"empty allow entry", Config{Upstreams: []Upstream{{Name: "a", URL: good, ToolsAllow: []string{" "}}}}},
		{"empty deny entry", Config{Upstreams: []Upstream{{Name: "a", URL: good, ToolsDeny: []string{""}}}}},
	}
	for _, tc := range cases {
		cfg := tc.cfg
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestLoadConfigWithPolicyFields(t *testing.T) {
	path := writeConfig(t, `{"upstreams":[{"name":"a","url":"http://127.0.0.1:3001/mcp","tools_deny":["delete_file","exec"]}]}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Upstreams[0].ToolsDeny; len(got) != 2 || got[0] != "delete_file" {
		t.Errorf("tools_deny = %v", got)
	}
}
