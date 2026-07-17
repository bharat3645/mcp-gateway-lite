package gateway

import (
	"bytes"
	"encoding/json"
)

// rpcSummary is what the audit log records about a JSON-RPC payload:
// method names, request ids, and tool names for tools/call — never
// params or arguments, which may hold secrets or user content.
type rpcSummary struct {
	// Methods lists the JSON-RPC method names, in order.
	Methods []string

	// IDs lists the raw JSON request ids (string ids keep their
	// quoting). Notifications contribute nothing here.
	IDs []string

	// Tools lists params.name for each tools/call message.
	Tools []string

	// ToolCalls counts tools/call messages, including ones whose tool
	// name could not be extracted — allowlist policies need to see
	// that discrepancy instead of failing open.
	ToolCalls int

	// ToolsListIDs lists the raw ids of tools/list requests, for
	// matching their responses on the way back.
	ToolsListIDs []string

	// Batch reports whether the payload was a JSON-RPC batch array.
	Batch bool

	// Invalid reports that the body could not be parsed as JSON (or
	// exceeded the metadata peek cap).
	Invalid bool
}

// rpcProbe decodes only the JSON-RPC fields the audit log needs.
type rpcProbe struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id"`
	Params json.RawMessage `json:"params"`
}

// summarizeRPC extracts a metadata-only summary from a JSON-RPC 2.0
// payload (single message or batch). Client-to-server response
// messages (result/error with no method) are valid Streamable HTTP
// POSTs and are not marked invalid.
func summarizeRPC(body []byte) rpcSummary {
	var s rpcSummary
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return s
	}
	switch body[0] {
	case '{':
		var p rpcProbe
		if err := json.Unmarshal(body, &p); err != nil {
			s.Invalid = true
			return s
		}
		addProbe(&s, p)
	case '[':
		var ps []rpcProbe
		if err := json.Unmarshal(body, &ps); err != nil || len(ps) == 0 {
			s.Invalid = true
			return s
		}
		s.Batch = true
		for _, p := range ps {
			addProbe(&s, p)
		}
	default:
		s.Invalid = true
	}
	return s
}

func addProbe(s *rpcSummary, p rpcProbe) {
	if p.Method != "" {
		s.Methods = append(s.Methods, p.Method)
	}
	hasID := len(p.ID) > 0 && string(p.ID) != "null"
	if hasID {
		s.IDs = append(s.IDs, string(p.ID))
	}
	if p.Method == "tools/list" && hasID {
		s.ToolsListIDs = append(s.ToolsListIDs, string(p.ID))
	}
	if p.Method == "tools/call" {
		s.ToolCalls++
		if len(p.Params) > 0 {
			var np struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(p.Params, &np); err == nil && np.Name != "" {
				s.Tools = append(s.Tools, np.Name)
			}
		}
	}
}
