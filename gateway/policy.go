package gateway

// toolPolicy is a precomputed allow/deny set for one upstream's
// tools/call traffic. nil means "no policy".
type toolPolicy struct {
	// allow, when non-nil, is an exhaustive allowlist: any tools/call
	// outside it is blocked, and unparseable bodies are blocked too —
	// default-deny needs verifiable input.
	allow map[string]bool

	// deny blocks matching tools/call names. Unparseable bodies pass
	// through — a blocklist is best-effort by nature.
	deny map[string]bool
}

func newToolPolicy(u Upstream) *toolPolicy {
	if len(u.ToolsAllow) == 0 && len(u.ToolsDeny) == 0 {
		return nil
	}
	p := &toolPolicy{}
	if len(u.ToolsAllow) > 0 {
		p.allow = make(map[string]bool, len(u.ToolsAllow))
		for _, tool := range u.ToolsAllow {
			p.allow[tool] = true
		}
	}
	if len(u.ToolsDeny) > 0 {
		p.deny = make(map[string]bool, len(u.ToolsDeny))
		for _, tool := range u.ToolsDeny {
			p.deny[tool] = true
		}
	}
	return p
}

// blockReason reports why a request must be blocked, or "" to let it
// through. Batch semantics: one blocked tool rejects the whole
// request. Non-tools/call traffic is never affected.
func (p *toolPolicy) blockReason(sum rpcSummary) string {
	if p == nil {
		return ""
	}
	if p.allow != nil {
		if sum.Invalid {
			return "tool policy: body not parseable, allowlist mode is default-deny"
		}
		if sum.ToolCalls > len(sum.Tools) {
			return "tool policy: tools/call without a parseable tool name"
		}
		for _, tool := range sum.Tools {
			if !p.allow[tool] {
				return "tool blocked by policy: " + tool
			}
		}
		return ""
	}
	for _, tool := range sum.Tools {
		if p.deny[tool] {
			return "tool blocked by policy: " + tool
		}
	}
	return ""
}

// allows reports whether the policy lets clients see and call the
// named tool. A nil policy allows everything. Used when filtering
// tools/list responses.
func (p *toolPolicy) allows(name string) bool {
	if p == nil {
		return true
	}
	if p.allow != nil {
		return p.allow[name]
	}
	return !p.deny[name]
}
