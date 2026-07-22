package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Entry is one audit record: request and response metadata only.
// Bodies, JSON-RPC params, and tool arguments are never written.
type Entry struct {
	// Time is the RFC 3339 (nanosecond, UTC) time the request arrived.
	Time string `json:"ts"`

	// Upstream is the route name, or empty for unknown-route attempts.
	Upstream string `json:"upstream"`

	// Remote is the client address as seen by the gateway.
	Remote string `json:"remote,omitempty"`

	// HTTPMethod is the inbound HTTP method.
	HTTPMethod string `json:"http_method"`

	// Path is the inbound request path.
	Path string `json:"path"`

	// SessionID echoes the Mcp-Session-Id request header.
	SessionID string `json:"session_id,omitempty"`

	// ProtocolVersion echoes the MCP-Protocol-Version request header.
	ProtocolVersion string `json:"protocol_version,omitempty"`

	// RPCMethods lists JSON-RPC method names found in the body.
	RPCMethods []string `json:"rpc_methods,omitempty"`

	// RPCIDs lists raw JSON-RPC request ids found in the body.
	RPCIDs []string `json:"rpc_ids,omitempty"`

	// Tools lists tools/call tool names found in the body.
	Tools []string `json:"tools,omitempty"`

	// RPCBatch reports whether the body was a JSON-RPC batch.
	RPCBatch bool `json:"rpc_batch,omitempty"`

	// RPCInvalid reports that the body was not parseable JSON or
	// exceeded the 1 MiB metadata cap. The request is proxied either
	// way.
	RPCInvalid bool `json:"rpc_invalid,omitempty"`

	// ToolsFiltered counts tools removed from this request's
	// tools/list response by the upstream's tool policy.
	ToolsFiltered int `json:"tools_filtered,omitempty"`

	// ToolsDrift reports that tools_lock verification failed for this
	// request's tools/list response. Error carries the detail; in
	// enforce mode the response was replaced with a JSON-RPC -32004
	// error, in warn mode it passed through.
	ToolsDrift bool `json:"tools_drift,omitempty"`

	// PromptProofVerdict is the worst promptproof verdict across this
	// request's scanned tools/call results ("suspicious"/"dangerous"),
	// empty if nothing was scanned or everything came back ok.
	PromptProofVerdict string `json:"promptproof_verdict,omitempty"`

	// PromptProofScore is the promptproof aggregate score for the worst
	// scanned result.
	PromptProofScore int `json:"promptproof_score,omitempty"`

	// PromptProofCategories lists the promptproof finding categories seen
	// (metadata only — never the matched content).
	PromptProofCategories []string `json:"promptproof_categories,omitempty"`

	// PromptProofBlocked reports that a tools/call result was replaced
	// with a JSON-RPC -32005 error because it met the configured
	// threshold under the block action.
	PromptProofBlocked bool `json:"promptproof_blocked,omitempty"`

	// PromptProofError records a scanner failure (coprocess error or
	// timeout). The result passes through unscanned (fail-open); the
	// error is surfaced here so a broken scanner is visible.
	PromptProofError string `json:"promptproof_error,omitempty"`

	// Status is the HTTP status returned to the client.
	Status int `json:"status"`

	// SSE reports whether the response was a text/event-stream.
	SSE bool `json:"sse,omitempty"`

	// BytesIn is the request body size in bytes.
	BytesIn int64 `json:"bytes_in"`

	// BytesOut is the response body size in bytes, as sent to the
	// client (a filtered tools/list response counts post-filtering).
	BytesOut int64 `json:"bytes_out"`

	// DurationMS is the wall-clock request duration in milliseconds.
	DurationMS float64 `json:"duration_ms"`

	// Error records proxy-level failures and policy verdicts, e.g. an
	// unreachable upstream, an unknown route, or a response-processing
	// block reason.
	Error string `json:"error,omitempty"`
}

// Auditor serializes Entry values as JSON Lines. Write failures are
// reported once to stderr and never fail the request path.
type Auditor struct {
	mu sync.Mutex

	w io.Writer

	closer io.Closer

	failed bool
}

// NewAuditor opens the audit sink described by cfg: a file path
// (append-only, created 0600) or "-"/empty for stdout.
func NewAuditor(cfg AuditConfig) (*Auditor, error) {
	if cfg.Path == "" || cfg.Path == "-" {
		return &Auditor{w: os.Stdout}, nil
	}
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", cfg.Path, err)
	}
	return &Auditor{w: f, closer: f}, nil
}

// NewAuditorWriter wraps an arbitrary writer. It exists mainly for
// tests and embedding.
func NewAuditorWriter(w io.Writer) *Auditor {
	return &Auditor{w: w}
}

// Log writes one JSON line. It is safe for concurrent use.
func (a *Auditor) Log(e Entry) {
	line, err := json.Marshal(e)
	if err != nil {
		a.reportFailure(err)
		return
	}
	line = append(line, '\n')
	a.mu.Lock()
	_, err = a.w.Write(line)
	a.mu.Unlock()
	if err != nil {
		a.reportFailure(err)
	}
}

func (a *Auditor) reportFailure(err error) {
	a.mu.Lock()
	first := !a.failed
	a.failed = true
	a.mu.Unlock()
	if first {
		fmt.Fprintf(os.Stderr, "mcp-gateway-lite: audit write failed (further failures suppressed): %v\n", err)
	}
}

// Close closes a file-backed sink. It is a no-op for writer-backed
// auditors.
func (a *Auditor) Close() error {
	if a.closer != nil {
		return a.closer.Close()
	}
	return nil
}

// now returns the RFC 3339 nanosecond UTC timestamp used in entries.
func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
