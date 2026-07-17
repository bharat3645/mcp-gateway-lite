package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
)

// wellKnownPrefix is the RFC 9728 path-insertion prefix the gateway
// serves protected-resource metadata under — one document per
// upstream: /.well-known/oauth-protected-resource/mcp/<name>.
const wellKnownPrefix = "/.well-known/oauth-protected-resource/mcp/"

// resourceMetadata is the RFC 9728 protected-resource metadata the
// gateway generates for an upstream.
type resourceMetadata struct {
	// Resource is the protected resource identifier — the gateway URL
	// clients actually talk to, not the internal upstream URL.
	Resource string `json:"resource"`

	// AuthorizationServers lists the issuers that protect this
	// resource, straight from upstream config.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`

	// BearerMethodsSupported is fixed to header-only: MCP clients send
	// Authorization headers; the gateway never accepts tokens in URLs.
	BearerMethodsSupported []string `json:"bearer_methods_supported"`

	// ResourceName is the optional human-readable name.
	ResourceName string `json:"resource_name,omitempty"`
}

// handleWellKnown serves generated protected-resource metadata. These
// requests are metadata reads, not MCP traffic, and are not audited
// (same policy as /healthz).
func (g *Gateway) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, wellKnownPrefix)
	u, ok := g.upstreams[name]
	if !ok {
		writeJSONError(w, http.StatusNotFound, -32001, "unknown resource")
		return
	}
	base := g.cfg.PublicBaseURL
	if base == "" {
		base = "http://" + r.Host
	}
	var md resourceMetadata
	md.Resource = strings.TrimSuffix(base, "/") + "/mcp/" + name
	md.AuthorizationServers = u.AuthorizationServers
	md.BearerMethodsSupported = []string{"header"}
	md.ResourceName = u.ResourceName
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if err := json.NewEncoder(w).Encode(md); err != nil {
		// The write already started; nothing safe to add. The client
		// sees a truncated body and retries.
		return
	}
}
