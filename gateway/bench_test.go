package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// benchToolResult is the tool result the scanning benchmarks push through
// promptproof each iteration — a realistic few-hundred-byte clean result.
const benchToolResult = `The query returned 3 rows. Customer 4471 (Acme Corp) has an ` +
	`overdue invoice from March; the other two are current. No action was taken.`

// BenchmarkThroughGatewayWithPromptProof measures the same tools/call round
// trip as BenchmarkThroughGateway but with promptproof scanning enabled on
// the upstream. The delta against BenchmarkThroughGateway is the per-call
// overhead promptproof adds: the length-prefixed frame to the serve
// coprocess, the scan itself, and parsing the JSON verdict back. Requires
// the real promptproof binary (skips if absent).
func BenchmarkThroughGatewayWithPromptProof(b *testing.B) {
	bin := findPromptproofBin()
	if bin == "" {
		b.Skip("promptproof binary not found; set PROMPTPROOF_BIN")
	}
	result := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"` + benchToolResult + `"}]}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(result))
	}))
	defer upstream.Close()

	cfg := Config{Upstreams: []Upstream{{
		Name:        "bench",
		URL:         upstream.URL,
		PromptProof: &PromptProofConfig{Enabled: true, Binary: bin, Action: "block", Threshold: "dangerous", Pool: 4},
	}}}
	gw, err := New(cfg, NewAuditorWriter(io.Discard))
	if err != nil {
		b.Fatal(err)
	}
	defer gw.Close()
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

// BenchmarkScannerScan isolates just the coprocess round trip (frame out,
// verdict in) with no HTTP in the path — the lower bound on the scan cost.
func BenchmarkScannerScan(b *testing.B) {
	bin := findPromptproofBin()
	if bin == "" {
		b.Skip("promptproof binary not found; set PROMPTPROOF_BIN")
	}
	sc, err := newScanner(&PromptProofConfig{Enabled: true, Binary: bin, Pool: 1})
	if err != nil {
		b.Fatal(err)
	}
	defer sc.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sc.Scan(benchToolResult); err != nil {
			b.Fatal(err)
		}
	}
}

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
