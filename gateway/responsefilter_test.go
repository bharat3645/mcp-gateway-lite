package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// gatewayWith builds a gateway around a single upstream config and
// returns the test server plus the audit buffer.
func gatewayWith(t *testing.T, u Upstream) (*httptest.Server, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	gw, err := New(Config{Upstreams: []Upstream{u}}, NewAuditorWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)
	return srv, buf
}

// fixedUpstream serves the same response to every request.
func fixedUpstream(t *testing.T, contentType string, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func postBody(t *testing.T, url, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(got)
}

const toolsListReq = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

func TestToolsListResponseFilteredDeny(t *testing.T) {
	upstream := fixedUpstream(t, "application/json",
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","inputSchema":{"maxSize":1.50}},{"name":"delete_file"},{"name":"search"}],"nextCursor":"page2"}}`)
	u := Upstream{Name: "files", URL: upstream.URL}
	u.ToolsDeny = []string{"delete_file"}
	gw, buf := gatewayWith(t, u)

	status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	if strings.Contains(body, "delete_file") {
		t.Fatalf("denied tool leaked into tools/list response: %s", body)
	}
	for _, want := range []string{`"read_file"`, `"search"`, `"nextCursor":"page2"`, "1.50"} {
		if !strings.Contains(body, want) {
			t.Errorf("filtered response lost %s: %s", want, body)
		}
	}
	var msg struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &msg); err != nil {
		t.Fatalf("filtered response is not valid JSON: %v: %s", err, body)
	}
	if len(msg.Result.Tools) != 2 {
		t.Errorf("tools = %+v, want 2 entries", msg.Result.Tools)
	}

	entries := waitForEntries(t, buf, 1)
	e := entries[0]
	if e.ToolsFiltered != 1 {
		t.Errorf("tools_filtered = %d, want 1", e.ToolsFiltered)
	}
	if e.Status != http.StatusOK {
		t.Errorf("status = %d", e.Status)
	}
	if len(e.RPCMethods) != 1 || e.RPCMethods[0] != "tools/list" {
		t.Errorf("rpc_methods = %v", e.RPCMethods)
	}
	if e.Error != "" {
		t.Errorf("error = %q, want none for a plain filter", e.Error)
	}
}

func TestToolsListResponseFilteredAllow(t *testing.T) {
	upstream := fixedUpstream(t, "application/json",
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file"},{"name":"write_file"},{"name":"exec"}]}}`)
	u := Upstream{Name: "files", URL: upstream.URL}
	u.ToolsAllow = []string{"read_file"}
	gw, buf := gatewayWith(t, u)

	status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	if strings.Contains(body, "write_file") || strings.Contains(body, "exec") {
		t.Fatalf("unlisted tools leaked: %s", body)
	}
	if !strings.Contains(body, "read_file") {
		t.Fatalf("allowlisted tool missing: %s", body)
	}
	entries := waitForEntries(t, buf, 1)
	if entries[0].ToolsFiltered != 2 {
		t.Errorf("tools_filtered = %d, want 2", entries[0].ToolsFiltered)
	}
}

func TestToolsListNamelessEntryBlockedInAllowMode(t *testing.T) {
	upstream := fixedUpstream(t, "application/json",
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"description":"tool with no name"}]}}`)
	u := Upstream{Name: "files", URL: upstream.URL}
	u.ToolsAllow = []string{"read_file"}
	gw, buf := gatewayWith(t, u)

	status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", status, body)
	}
	if !strings.Contains(body, "-32003") || !strings.Contains(body, "without a tool name") {
		t.Fatalf("403 body = %s", body)
	}
	entries := waitForEntries(t, buf, 1)
	e := entries[0]
	if e.Status != http.StatusForbidden {
		t.Errorf("audited status = %d", e.Status)
	}
	if !strings.Contains(e.Error, "without a tool name") {
		t.Errorf("audited error = %q", e.Error)
	}
}

func TestToolsListCleanResponseByteIdentical(t *testing.T) {
	// Deliberately weird-but-valid spacing and number formats: when no
	// tool is filtered the client must receive exactly the upstream
	// bytes, proving the gateway does not decode/re-encode on the
	// happy path.
	orig := "{\"jsonrpc\" : \"2.0\" ,\"id\":1,   \"result\":{\"tools\":[{\"name\":\"read_file\"}],\"x\":[1.50,2e3]}}"
	upstream := fixedUpstream(t, "application/json", orig)
	u := Upstream{Name: "files", URL: upstream.URL}
	u.ToolsDeny = []string{"delete_file"}
	gw, _ := gatewayWith(t, u)

	status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if body != orig {
		t.Fatalf("clean response was rewritten:\n got %q\nwant %q", body, orig)
	}
}

func TestToolsListGarbageResponse(t *testing.T) {
	t.Run("allow mode blocks", func(t *testing.T) {
		upstream := fixedUpstream(t, "application/json", "not json at all")
		u := Upstream{Name: "files", URL: upstream.URL}
		u.ToolsAllow = []string{"read_file"}
		gw, buf := gatewayWith(t, u)

		status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
		if status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body = %s", status, body)
		}
		if !strings.Contains(body, "not parseable") {
			t.Fatalf("403 body = %s", body)
		}
		entries := waitForEntries(t, buf, 1)
		if !strings.Contains(entries[0].Error, "not parseable") {
			t.Errorf("audited error = %q", entries[0].Error)
		}
	})
	t.Run("deny mode passes verbatim", func(t *testing.T) {
		upstream := fixedUpstream(t, "application/json", "not json at all")
		u := Upstream{Name: "files", URL: upstream.URL}
		u.ToolsDeny = []string{"delete_file"}
		gw, _ := gatewayWith(t, u)

		status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
		if status != http.StatusOK || body != "not json at all" {
			t.Fatalf("status = %d, body = %q", status, body)
		}
	})
}

func TestNonToolsListResultsUntouched(t *testing.T) {
	// The response carries a result with a "tools"-shaped array under
	// an id that does NOT belong to a tools/list request. Rewriting it
	// would corrupt someone's data; it must pass byte-exact.
	orig := `{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"delete_file"}],"note":"tool-call output, not a listing"}}`
	upstream := fixedUpstream(t, "application/json", orig)
	u := Upstream{Name: "files", URL: upstream.URL}
	u.ToolsDeny = []string{"delete_file"}
	gw, _ := gatewayWith(t, u)

	// Request contains tools/list (id 1) so response processing is
	// armed — but the response answers id 7.
	status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if body != orig {
		t.Fatalf("non-candidate result was rewritten:\n got %q\nwant %q", body, orig)
	}
}

func TestToolsListOversizedResponse(t *testing.T) {
	big := `{"jsonrpc":"2.0","id":1,"result":{"pad":"` + strings.Repeat("x", maxRPCPeek+4096) + `"}}`
	t.Run("deny mode passes byte-complete", func(t *testing.T) {
		upstream := fixedUpstream(t, "application/json", big)
		u := Upstream{Name: "files", URL: upstream.URL}
		u.ToolsDeny = []string{"delete_file"}
		gw, _ := gatewayWith(t, u)

		status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
		if status != http.StatusOK {
			t.Fatalf("status = %d", status)
		}
		if len(body) != len(big) {
			t.Fatalf("body length = %d, want %d (byte-complete passthrough)", len(body), len(big))
		}
	})
	t.Run("allow mode blocks", func(t *testing.T) {
		upstream := fixedUpstream(t, "application/json", big)
		u := Upstream{Name: "files", URL: upstream.URL}
		u.ToolsAllow = []string{"read_file"}
		gw, _ := gatewayWith(t, u)

		status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
		if status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", status)
		}
		if !strings.Contains(body, "processing cap") {
			t.Fatalf("403 body = %s", body)
		}
	})
}

func TestToolsListResponseFilteredSSE(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream writer is not a flusher")
			return
		}
		fmt.Fprint(w, ": keepalive\n\n")
		fmt.Fprint(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"read_file\"},{\"name\":\"delete_file\"}],\"nextCursor\":\"n1\"}}\n\n")
		fl.Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"ok\":true}}\n\n")
		fl.Flush()
	}))
	t.Cleanup(upstream.Close)

	u := Upstream{Name: "files", URL: upstream.URL}
	u.ToolsDeny = []string{"delete_file"}
	gw, buf := gatewayWith(t, u)

	resp, err := http.Post(gw.URL+"/mcp/files", "application/json", strings.NewReader(toolsListReq))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	reader := bufio.NewReader(resp.Body)
	var pre strings.Builder
	// Read through the end of the filtered tools event (two blank
	// lines' worth of events) while the upstream is still blocked —
	// this proves events flow through the rewriter mid-stream.
	blanks := 0
	for blanks < 2 {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended early: %v (got %q)", err, pre.String())
		}
		pre.WriteString(line)
		if line == "\n" {
			blanks++
		}
	}
	got := pre.String()
	if !strings.Contains(got, ": keepalive\n") {
		t.Errorf("keepalive comment lost: %q", got)
	}
	if !strings.Contains(got, "event: message\n") {
		t.Errorf("event field lost: %q", got)
	}
	if strings.Contains(got, "delete_file") {
		t.Errorf("denied tool leaked mid-stream: %q", got)
	}
	if !strings.Contains(got, "read_file") || !strings.Contains(got, "nextCursor") {
		t.Errorf("filtered event lost content: %q", got)
	}

	close(release)
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rest), `{"jsonrpc":"2.0","id":9,"result":{"ok":true}}`) {
		t.Errorf("post-release event mangled: %q", rest)
	}

	entries := waitForEntries(t, buf, 1)
	e := entries[0]
	if !e.SSE {
		t.Error("expected sse=true")
	}
	if e.ToolsFiltered != 1 {
		t.Errorf("tools_filtered = %d, want 1", e.ToolsFiltered)
	}
}

func TestSSENonCandidateEventsVerbatim(t *testing.T) {
	// CRLF terminators, comments, id fields, multi-data events, no
	// space after the colon, unparseable data — none of it is a
	// candidate (ids differ), so every byte must survive.
	orig := ": comment with trailing space \r\n" +
		"id: 44\r\n" +
		"data:{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[{\"name\":\"delete_file\"}]}}\r\n" +
		"\r\n" +
		"data: first\n" +
		"data: second\n" +
		"\n" +
		"data: <<<not json>>>\n" +
		"\n"
	for _, mode := range []string{"deny", "allow"} {
		t.Run(mode, func(t *testing.T) {
			upstream := fixedUpstream(t, "text/event-stream", orig)
			u := Upstream{Name: "files", URL: upstream.URL}
			if mode == "deny" {
				u.ToolsDeny = []string{"delete_file"}
			} else {
				u.ToolsAllow = []string{"read_file"}
			}
			gw, _ := gatewayWith(t, u)

			status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
			if status != http.StatusOK {
				t.Fatalf("status = %d", status)
			}
			if body != orig {
				t.Fatalf("non-candidate SSE bytes changed:\n got %q\nwant %q", body, orig)
			}
		})
	}
}

func TestSSEOversizedEvent(t *testing.T) {
	huge := "data: " + strings.Repeat("y", maxRPCPeek+4096) + "\n\n"
	tail := "data: {\"jsonrpc\":\"2.0\",\"id\":8,\"result\":{\"after\":true}}\n\n"
	t.Run("deny mode passes verbatim", func(t *testing.T) {
		upstream := fixedUpstream(t, "text/event-stream", huge+tail)
		u := Upstream{Name: "files", URL: upstream.URL}
		u.ToolsDeny = []string{"delete_file"}
		gw, _ := gatewayWith(t, u)

		status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
		if status != http.StatusOK {
			t.Fatalf("status = %d", status)
		}
		if len(body) != len(huge)+len(tail) {
			t.Fatalf("body length = %d, want %d", len(body), len(huge)+len(tail))
		}
		if !strings.HasSuffix(body, tail) {
			t.Fatalf("stream did not resume after oversized event: %q", body[len(body)-100:])
		}
	})
	t.Run("allow mode replaces with error and continues", func(t *testing.T) {
		upstream := fixedUpstream(t, "text/event-stream", huge+tail)
		u := Upstream{Name: "files", URL: upstream.URL}
		u.ToolsAllow = []string{"read_file"}
		gw, buf := gatewayWith(t, u)

		status, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
		if status != http.StatusOK {
			t.Fatalf("status = %d", status)
		}
		if strings.Contains(body, "yyyy") {
			t.Fatal("oversized event leaked in strict mode")
		}
		if !strings.Contains(body, "exceeded the processing cap") {
			t.Fatalf("missing cap error event: %q", body)
		}
		if !strings.HasSuffix(body, tail) {
			t.Fatalf("stream did not resume after discarded event: %q", body)
		}
		entries := waitForEntries(t, buf, 1)
		if !strings.Contains(entries[0].Error, "processing cap") {
			t.Errorf("audited error = %q", entries[0].Error)
		}
	})
}

// chunkReader serves its data in fixed-size chunks so streaming state
// machines can be tested across arbitrary read boundaries.
type chunkReader struct {
	data []byte
	size int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := c.size
	if n > len(c.data) {
		n = len(c.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func TestSSERewriterChunkingInvariance(t *testing.T) {
	stream := ": comment\n\n" +
		"id: s1\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"read_file\"},{\"name\":\"delete_file\"}]}}\r\n\r\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\ndata: \"result\":{\"tools\":[{\"name\":\"delete_file\"}]}}\n\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{\"ok\":true}}\n\n" +
		"data: <<<garbage>>>\n\n" +
		"data: partial tail with no terminator"
	newState := func() *rewriteState {
		return &rewriteState{
			ids:    []string{"1"},
			policy: newToolPolicy(Upstream{ToolsDeny: []string{"delete_file"}}),
		}
	}
	run := func(size int) (string, int) {
		st := newState()
		r := newSSERewriter(io.NopCloser(&chunkReader{data: []byte(stream), size: size}), st)
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		return string(out), st.filtered
	}
	ref, refFiltered := run(len(stream))
	if strings.Contains(ref, "delete_file") {
		t.Fatalf("candidate events not filtered: %q", ref)
	}
	if refFiltered != 2 {
		t.Fatalf("filtered = %d, want 2", refFiltered)
	}
	for _, want := range []string{": comment\n\n", "id: s1\r\n", `"id":6`, "<<<garbage>>>", "partial tail with no terminator"} {
		if !strings.Contains(ref, want) {
			t.Fatalf("reference output lost %q: %q", want, ref)
		}
	}
	for _, size := range []int{1, 2, 3, 5, 8, 16, 64, 1024} {
		got, filtered := run(size)
		if got != ref {
			t.Errorf("chunk size %d: output differs\n got %q\nwant %q", size, got, ref)
		}
		if filtered != refFiltered {
			t.Errorf("chunk size %d: filtered = %d, want %d", size, filtered, refFiltered)
		}
	}
}

func TestBatchToolsListResponseFiltered(t *testing.T) {
	upstream := fixedUpstream(t, "application/json",
		`[{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_file"}],"note":"ping data, not a listing"}},`+
			`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_file"},{"name":"delete_file"}]}}]`)
	u := Upstream{Name: "files", URL: upstream.URL}
	u.ToolsDeny = []string{"delete_file"}
	gw, buf := gatewayWith(t, u)

	req := `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`
	status, body := postBody(t, gw.URL+"/mcp/files", req)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	var msgs []struct {
		ID     int `json:"id"`
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
			Note string `json:"note"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &msgs); err != nil {
		t.Fatalf("batch response unparseable: %v: %s", err, body)
	}
	if len(msgs) != 2 {
		t.Fatalf("messages = %d", len(msgs))
	}
	// id 1 is the ping's result: its "tools"-shaped data is NOT a
	// tools/list result and must survive.
	if len(msgs[0].Result.Tools) != 1 || msgs[0].Result.Tools[0].Name != "delete_file" {
		t.Errorf("ping result was corrupted: %+v", msgs[0].Result)
	}
	if msgs[0].Result.Note != "ping data, not a listing" {
		t.Errorf("ping note lost: %+v", msgs[0].Result)
	}
	// id 2 is the real tools/list: filtered.
	if len(msgs[1].Result.Tools) != 1 || msgs[1].Result.Tools[0].Name != "read_file" {
		t.Errorf("tools/list result not filtered: %+v", msgs[1].Result)
	}
	entries := waitForEntries(t, buf, 1)
	if entries[0].ToolsFiltered != 1 {
		t.Errorf("tools_filtered = %d, want 1", entries[0].ToolsFiltered)
	}
}

func TestAcceptEncodingStrippedForCandidateRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":9,"result":{"ae":%q}}`, r.Header.Get("Accept-Encoding"))
	}))
	t.Cleanup(upstream.Close)
	u := Upstream{Name: "files", URL: upstream.URL}
	u.ToolsDeny = []string{"delete_file"}
	gw, _ := gatewayWith(t, u)

	// Candidate (tools/list): Accept-Encoding must be stripped so the
	// response is parseable.
	_, body := postBody(t, gw.URL+"/mcp/files", toolsListReq)
	if !strings.Contains(body, `"ae":""`) {
		t.Errorf("candidate request kept Accept-Encoding: %s", body)
	}
	// Non-candidate: the client's Accept-Encoding passes through
	// (Go's client sends gzip by default).
	_, body = postBody(t, gw.URL+"/mcp/files", `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if !strings.Contains(body, "gzip") {
		t.Errorf("non-candidate request lost Accept-Encoding: %s", body)
	}
}

func TestWriteJSONErrorAlwaysValidJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSONError(rec, http.StatusForbidden, -32003, "tool blocked by policy: bad\x01name \"quoted\" \\slash\x7f")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if !json.Valid(rec.Body.Bytes()) {
		t.Fatalf("writeJSONError produced invalid JSON: %q", rec.Body.String())
	}
}
