// Package gateway implements a minimal, stateless reverse proxy for
// MCP (Model Context Protocol) Streamable HTTP servers with a JSON
// Lines audit trail.
//
// Requests to /mcp/<name> (and any subpath) are forwarded to the
// upstream registered under <name>. Every proxied request produces
// exactly one audit entry containing metadata only — JSON-RPC method
// names, request ids, and tools/call tool names — never params,
// arguments, or bodies.
package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// maxRPCPeek caps how much of a request body is buffered for JSON-RPC
// metadata extraction. Larger bodies are still proxied in full; they
// are just recorded with rpc_invalid=true instead of being parsed.
const maxRPCPeek = 1 << 20

// defaultHeaderTimeout bounds the wait for upstream response headers
// when an upstream does not set HeaderTimeoutSeconds. The response
// body is deliberately unbounded so SSE streams can stay open.
const defaultHeaderTimeout = 30 * time.Second

type ctxKey int

// proxyErrKey carries a *string that the proxy ErrorHandler fills in,
// so the audit entry can record why an upstream call failed.
const proxyErrKey ctxKey = 0

// Gateway is an http.Handler that routes /mcp/<name> to configured
// upstreams and audits every request. Use New to build one.
type Gateway struct {
	// cfg is the validated configuration the gateway was built with.
	cfg Config

	// auditor receives one Entry per handled /mcp request.
	auditor *Auditor

	// routes maps upstream name to its reverse proxy.
	routes map[string]*httputil.ReverseProxy

	// upstreams maps upstream name to its validated config, used for
	// .well-known metadata generation.
	upstreams map[string]Upstream

	// limits maps upstream name to its token bucket; a missing entry
	// means unlimited.
	limits map[string]*tokenBucket

	// policies maps upstream name to its tool policy; nil means no
	// policy.
	policies map[string]*toolPolicy
}

// New validates cfg and builds a Gateway. The auditor must not be
// nil: the audit trail is not optional in this proxy — it is the
// point of it.
func New(cfg Config, auditor *Auditor) (*Gateway, error) {
	if auditor == nil {
		return nil, errors.New("gateway: auditor must not be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	g := &Gateway{cfg: cfg, auditor: auditor}
	g.routes = make(map[string]*httputil.ReverseProxy, len(cfg.Upstreams))
	g.upstreams = make(map[string]Upstream, len(cfg.Upstreams))
	g.limits = make(map[string]*tokenBucket)
	g.policies = make(map[string]*toolPolicy)
	for _, u := range cfg.Upstreams {
		p, err := newProxy(u)
		if err != nil {
			return nil, fmt.Errorf("gateway: upstream %q: %w", u.Name, err)
		}
		g.routes[u.Name] = p
		g.upstreams[u.Name] = u
		if u.RateLimit != nil {
			g.limits[u.Name] = newTokenBucket(u.RateLimit.RequestsPerSecond, u.RateLimit.Burst, nil)
		}
		if pol := newToolPolicy(u); pol != nil {
			g.policies[u.Name] = pol
		}
	}
	return g, nil
}

// ServeHTTP implements http.Handler.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/healthz":
		g.handleHealth(w)
	case strings.HasPrefix(r.URL.Path, wellKnownPrefix):
		g.handleWellKnown(w, r)
	case strings.HasPrefix(r.URL.Path, "/mcp/"):
		g.handleProxy(w, r)
	default:
		writeJSONError(w, http.StatusNotFound, -32001, "not found")
	}
}

func (g *Gateway) handleHealth(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{\"status\":\"ok\",\"upstreams\":%d}\n", len(g.routes))
}

func (g *Gateway) handleProxy(w http.ResponseWriter, r *http.Request) {
	name, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/mcp/"), "/")
	proxy, ok := g.routes[name]
	if !ok {
		var e Entry
		e.Time = now()
		e.Remote = r.RemoteAddr
		e.HTTPMethod = r.Method
		e.Path = r.URL.Path
		e.Status = http.StatusNotFound
		e.Error = "unknown upstream"
		g.auditor.Log(e)
		writeJSONError(w, http.StatusNotFound, -32001, "unknown upstream")
		return
	}

	// Rate limiting happens before the body is read: a limited client
	// must not consume gateway bandwidth. The tradeoff is that 429
	// audit entries carry no rpc_* fields.
	if b := g.limits[name]; b != nil {
		if allowed, retry := b.allow(); !allowed {
			secs := int(math.Ceil(retry.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			var e Entry
			e.Time = now()
			e.Upstream = name
			e.Remote = r.RemoteAddr
			e.HTTPMethod = r.Method
			e.Path = r.URL.Path
			e.SessionID = r.Header.Get("Mcp-Session-Id")
			e.ProtocolVersion = r.Header.Get("MCP-Protocol-Version")
			e.Status = http.StatusTooManyRequests
			e.Error = "rate limited"
			g.auditor.Log(e)
			writeJSONError(w, http.StatusTooManyRequests, -32002, "rate limited")
			return
		}
	}

	start := time.Now()

	var e Entry
	e.Time = now()
	e.Upstream = name
	e.Remote = r.RemoteAddr
	e.HTTPMethod = r.Method
	e.Path = r.URL.Path
	e.SessionID = r.Header.Get("Mcp-Session-Id")
	e.ProtocolVersion = r.Header.Get("MCP-Protocol-Version")

	// Peek at the request body for JSON-RPC metadata without
	// disturbing what the upstream receives.
	var extraIn atomic.Int64
	var buffered int64
	var sum rpcSummary
	if r.Body != nil && r.Body != http.NoBody {
		orig := r.Body
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, io.LimitReader(orig, maxRPCPeek+1)); err != nil {
			e.Error = "request body read: " + err.Error()
		}
		buffered = int64(buf.Len())
		if buffered <= maxRPCPeek {
			sum = summarizeRPC(buf.Bytes())
			r.Body = readCloser{Reader: bytes.NewReader(buf.Bytes()), Closer: orig}
		} else {
			sum.Invalid = true
			rest := &countingReader{rc: orig, n: &extraIn}
			r.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(buf.Bytes()), rest), Closer: orig}
		}
	}

	// Tool policy enforcement rides the same peek. Blocked requests
	// are fully audited — they are the entries operators care about
	// most.
	if reason := g.policies[name].blockReason(sum); reason != "" {
		e.RPCMethods = sum.Methods
		e.RPCIDs = sum.IDs
		e.Tools = sum.Tools
		e.RPCBatch = sum.Batch
		e.RPCInvalid = sum.Invalid
		e.Status = http.StatusForbidden
		e.BytesIn = buffered
		e.DurationMS = float64(time.Since(start).Microseconds()) / 1000.0
		e.Error = reason
		g.auditor.Log(e)
		writeJSONError(w, http.StatusForbidden, -32003, reason)
		return
	}

	rec := &countingWriter{ResponseWriter: w}
	var proxyErr string
	ctx := context.WithValue(r.Context(), proxyErrKey, &proxyErr)
	proxy.ServeHTTP(rec, r.WithContext(ctx))

	e.RPCMethods = sum.Methods
	e.RPCIDs = sum.IDs
	e.Tools = sum.Tools
	e.RPCBatch = sum.Batch
	e.RPCInvalid = sum.Invalid
	e.Status = rec.status
	if e.Status == 0 {
		e.Status = http.StatusOK
	}
	e.SSE = strings.HasPrefix(rec.Header().Get("Content-Type"), "text/event-stream")
	e.BytesIn = buffered + extraIn.Load()
	e.BytesOut = rec.written
	e.DurationMS = float64(time.Since(start).Microseconds()) / 1000.0
	if proxyErr != "" {
		e.Error = proxyErr
	}
	g.auditor.Log(e)
}

// newProxy builds the reverse proxy for one upstream.
func newProxy(u Upstream) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(u.URL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	prefix := "/mcp/" + u.Name
	timeout := defaultHeaderTimeout
	if u.HeaderTimeoutSeconds > 0 {
		timeout = time.Duration(u.HeaderTimeoutSeconds) * time.Second
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{}
	transport.Proxy = http.ProxyFromEnvironment
	transport.DialContext = dialer.DialContext
	transport.ForceAttemptHTTP2 = true
	transport.MaxIdleConns = 100
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = timeout

	rp := &httputil.ReverseProxy{}
	rp.Transport = transport
	rp.Rewrite = func(pr *httputil.ProxyRequest) {
		pr.SetXForwarded()
		out := *target
		out.Path = joinPath(target.Path, strings.TrimPrefix(pr.In.URL.Path, prefix))
		out.RawQuery = pr.In.URL.RawQuery
		pr.Out.URL = &out
		pr.Out.Host = target.Host
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if p, ok := r.Context().Value(proxyErrKey).(*string); ok {
			*p = err.Error()
		}
		if cw, ok := w.(*countingWriter); ok && cw.status != 0 {
			// The response already started streaming; there is nothing
			// safe left to write.
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintln(w, `{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"upstream unavailable"}}`)
	}
	return rp, nil
}

// joinPath joins the upstream base path with the request subpath,
// avoiding duplicate or missing slashes.
func joinPath(base, suffix string) string {
	base = strings.TrimSuffix(base, "/")
	if suffix == "" || suffix == "/" {
		if base == "" {
			return "/"
		}
		return base
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	if base == "" {
		return suffix
	}
	return base + suffix
}

// countingWriter wraps a ResponseWriter to record status and bytes
// for the audit entry while passing flushes through for SSE
// streaming.
type countingWriter struct {
	http.ResponseWriter

	status int

	written int64
}

func (w *countingWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *countingWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

// Flush passes streaming flushes through to the underlying writer so
// SSE events are delivered as they happen, not when the stream ends.
func (w *countingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *countingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// countingReader counts bytes read past the audit peek buffer so
// bytes_in stays accurate for oversized request bodies.
type countingReader struct {
	rc io.ReadCloser

	n *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// readCloser splices a replacement Reader onto the original request
// body's Closer.
type readCloser struct {
	io.Reader

	io.Closer
}

func writeJSONError(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":%d,\"message\":%q}}\n", code, msg)
}
