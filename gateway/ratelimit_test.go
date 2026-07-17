package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenBucketBurstAndRefill(t *testing.T) {
	cur := time.Unix(1000, 0)
	clock := func() time.Time { return cur }
	b := newTokenBucket(1, 2, clock)

	if ok, _ := b.allow(); !ok {
		t.Fatal("first request should pass")
	}
	if ok, _ := b.allow(); !ok {
		t.Fatal("second request should pass (burst)")
	}
	ok, retry := b.allow()
	if ok {
		t.Fatal("third request should be limited")
	}
	if retry <= 0 || retry > time.Second {
		t.Fatalf("retry = %v, want (0, 1s]", retry)
	}

	cur = cur.Add(1500 * time.Millisecond)
	if ok, _ := b.allow(); !ok {
		t.Fatal("request after refill should pass")
	}
	if ok, _ := b.allow(); ok {
		t.Fatal("only 1.5 tokens refilled; second request must fail")
	}

	cur = cur.Add(10 * time.Second)
	if ok, _ := b.allow(); !ok {
		t.Fatal("long idle: first should pass")
	}
	if ok, _ := b.allow(); !ok {
		t.Fatal("long idle: second should pass (cap = burst)")
	}
	if ok, _ := b.allow(); ok {
		t.Fatal("refill must cap at burst")
	}
}

func TestTokenBucketConcurrentCap(t *testing.T) {
	cur := time.Unix(0, 0)
	b := newTokenBucket(1, 5, func() time.Time { return cur })
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if ok, _ := b.allow(); ok {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != 5 {
		t.Fatalf("allowed = %d, want exactly burst (5) under a frozen clock", got)
	}
}

func TestRateLimitEndToEnd(t *testing.T) {
	upstream := echoUpstream(t)
	buf := &syncBuffer{}
	u := Upstream{Name: "files", URL: upstream.URL}
	u.RateLimit = &RateLimitConfig{RequestsPerSecond: 1, Burst: 2}
	gw, err := New(Config{Upstreams: []Upstream{u}}, NewAuditorWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)

	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	for i := 0; i < 2; i++ {
		resp, err := http.Post(srv.URL+"/mcp/files", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, resp.StatusCode)
		}
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp/files", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Mcp-Session-Id", "limited-session")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third request: status = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("429 response missing Retry-After")
	}

	entries := waitForEntries(t, buf, 3)
	e := entries[len(entries)-1]
	if e.Status != http.StatusTooManyRequests {
		t.Errorf("audited status = %d", e.Status)
	}
	if e.Error != "rate limited" {
		t.Errorf("audited error = %q", e.Error)
	}
	if e.Upstream != "files" {
		t.Errorf("audited upstream = %q", e.Upstream)
	}
	if e.SessionID != "limited-session" {
		t.Errorf("audited session_id = %q (429s must still be attributable)", e.SessionID)
	}
	if len(e.RPCMethods) != 0 {
		t.Errorf("rpc_methods = %v, want none (body is not read on 429)", e.RPCMethods)
	}
}

func TestNoRateLimitByDefault(t *testing.T) {
	upstream := echoUpstream(t)
	gw, buf := startGateway(t, "files", upstream.URL)

	for i := 0; i < 10; i++ {
		resp, err := http.Post(gw.URL+"/mcp/files", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d (no limit configured)", i, resp.StatusCode)
		}
	}
	waitForEntries(t, buf, 10)
}

func TestSessionLimiterIsolatesSessions(t *testing.T) {
	cur := time.Unix(0, 0)
	l := newSessionLimiter(1, 2, 8, func() time.Time { return cur })
	for i := 0; i < 2; i++ {
		if ok, _ := l.allow("a"); !ok {
			t.Fatalf("a burst %d must pass", i)
		}
	}
	if ok, _ := l.allow("a"); ok {
		t.Fatal("a should be exhausted")
	}
	if ok, _ := l.allow("b"); !ok {
		t.Fatal("b must not share a's bucket")
	}
	if ok, _ := l.allow(""); !ok {
		t.Fatal("the empty session gets its own shared bucket")
	}
}

func TestSessionLimiterEviction(t *testing.T) {
	cur := time.Unix(0, 0)
	l := newSessionLimiter(1, 1, 2, func() time.Time { return cur })
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("a")
	}
	cur = cur.Add(time.Millisecond)
	if ok, _ := l.allow("b"); !ok {
		t.Fatal("b")
	}
	cur = cur.Add(time.Millisecond)
	// c evicts a (least recently seen); a's return then gets a fresh
	// bucket — the documented consequence of bounding a table keyed
	// by untrusted ids.
	if ok, _ := l.allow("c"); !ok {
		t.Fatal("c")
	}
	if len(l.buckets) != 2 {
		t.Fatalf("buckets = %d, want 2 (bounded)", len(l.buckets))
	}
	cur = cur.Add(time.Millisecond)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("evicted session must get a fresh bucket")
	}
}

func TestPerSessionRateLimitEndToEnd(t *testing.T) {
	upstream := echoUpstream(t)
	buf := &syncBuffer{}
	u := Upstream{Name: "files", URL: upstream.URL}
	u.RateLimit = &RateLimitConfig{RequestsPerSecond: 0.001, Burst: 1, PerSession: true}
	gw, err := New(Config{Upstreams: []Upstream{u}}, NewAuditorWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)

	do := func(session string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp/files", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		if err != nil {
			t.Fatal(err)
		}
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := do("s1"); got != http.StatusOK {
		t.Fatalf("s1 first = %d", got)
	}
	if got := do("s1"); got != http.StatusTooManyRequests {
		t.Fatalf("s1 second = %d, want 429", got)
	}
	if got := do("s2"); got != http.StatusOK {
		t.Fatalf("s2 first = %d (sessions must not share buckets)", got)
	}
	if got := do(""); got != http.StatusOK {
		t.Fatalf("no-session first = %d", got)
	}
	if got := do(""); got != http.StatusTooManyRequests {
		t.Fatalf("no-session second = %d, want 429", got)
	}
	waitForEntries(t, buf, 5)
	if !strings.Contains(buf.String(), `"session_id":"s1"`) {
		t.Error("429 audit lost the session id")
	}
}
