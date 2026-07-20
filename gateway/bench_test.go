package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkDirectUpstream measures a bare tools/call round trip
// against the upstream test server with no proxy in the path — the
// baseline the gateway's overhead is measured against.
func BenchmarkDirectUpstream(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer upstream.Close()

	client := &http.Client{}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"noop","arguments":{}}}`)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Post(upstream.URL, "application/json", bytes.NewReader(body))
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// BenchmarkThroughGateway measures the same round trip through a
// real gateway.Gateway (audit trail to io.Discard, no rate limit, no
// policy, no lock — the minimal-config path) sitting in front of the
// same upstream. The delta against BenchmarkDirectUpstream is the
// proxy's per-request overhead: routing, audit-entry construction,
// and the ReverseProxy hop itself.
func BenchmarkThroughGateway(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer upstream.Close()

	cfg := Config{Upstreams: []Upstream{{Name: "bench", URL: upstream.URL}}}
	gw, err := New(cfg, NewAuditorWriter(io.Discard))
	if err != nil {
		b.Fatal(err)
	}
	front := httptest.NewServer(gw)
	defer front.Close()

	client := &http.Client{}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"noop","arguments":{}}}`)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Post(front.URL+"/mcp/bench", "application/json", bytes.NewReader(body))
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
