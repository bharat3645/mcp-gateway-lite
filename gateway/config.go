package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// DefaultListen is used when Config.Listen is empty. Loopback on
// purpose: exposing the gateway more widely should be an explicit
// operator choice, not a default.
const DefaultListen = "127.0.0.1:8385"

// nameRE constrains upstream names because they become URL path
// segments and audit-log values.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// RateLimitConfig is a per-upstream token-bucket limit.
type RateLimitConfig struct {
	// RequestsPerSecond is the sustained refill rate. Must be > 0.
	RequestsPerSecond float64 `json:"requests_per_second"`

	// Burst is the bucket capacity — the number of requests served
	// back-to-back before the sustained rate applies. Must be >= 1.
	Burst int `json:"burst"`

	// PerSession keys buckets by Mcp-Session-Id instead of one
	// gateway-wide bucket for the upstream. Session ids are
	// client-supplied, so this is fairness between honest clients,
	// not DoS protection; the bucket table is bounded with
	// least-recently-seen eviction.
	PerSession bool `json:"per_session,omitempty"`
}

// LockConfig wires an mcp-sentinel-format lockfile into the request
// path for one upstream: tools/list responses are verified against
// the locked tool fingerprints, and drift is blocked (enforce) or
// audited (warn).
type LockConfig struct {
	// File is the lockfile path. Required. Generate it with
	// --lock-init, or with `mcp-sentinel lock` from a tools capture.
	File string `json:"file"`

	// Server selects the lockfile server entry; defaults to the
	// upstream name.
	Server string `json:"server,omitempty"`

	// Mode is "enforce" (default: drifted tools/list responses are
	// replaced with a JSON-RPC -32004 error) or "warn" (drift passes
	// but is audited).
	Mode string `json:"mode,omitempty"`
}

// Upstream describes one MCP server behind the gateway.
type Upstream struct {
	// Name is the route segment: requests to /mcp/<Name> and any
	// subpath are forwarded to URL.
	Name string `json:"name"`

	// URL is the upstream MCP endpoint, e.g.
	// "http://127.0.0.1:3001/mcp". Scheme must be http or https, and
	// the URL must not carry a query string or fragment.
	URL string `json:"url"`

	// HeaderTimeoutSeconds bounds the wait for upstream response
	// headers (default 30). It deliberately does not bound the
	// response body, so SSE streams can stay open indefinitely.
	HeaderTimeoutSeconds int `json:"header_timeout_seconds,omitempty"`

	// RateLimit, when set, applies a token bucket to this upstream.
	// Exhaustion returns 429 with a Retry-After header and an audited
	// entry.
	RateLimit *RateLimitConfig `json:"rate_limit,omitempty"`

	// ToolsAllow, when non-empty, is an exhaustive allowlist for
	// tools/call: any other tool is blocked with 403, and unparseable
	// bodies are blocked too, because default-deny needs verifiable
	// input. tools/list responses are filtered to match. Mutually
	// exclusive with ToolsDeny.
	ToolsAllow []string `json:"tools_allow,omitempty"`

	// ToolsDeny blocks matching tools/call names with 403 and filters
	// them out of tools/list responses. Unparseable bodies pass
	// through — a blocklist is best-effort by nature.
	ToolsDeny []string `json:"tools_deny,omitempty"`

	// ToolsLock, when set, verifies tools/list responses against a
	// sentinel-format lockfile (the rug-pull check, inline).
	ToolsLock *LockConfig `json:"tools_lock,omitempty"`

	// AuthorizationServers is advertised in the generated RFC 9728
	// protected-resource metadata for this upstream.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`

	// ResourceName is the human-readable resource_name in the
	// generated metadata.
	ResourceName string `json:"resource_name,omitempty"`
}

// AuditConfig controls the JSON Lines audit log.
type AuditConfig struct {
	// Path is the destination: a file path (append-only, created
	// 0600), or "-" or empty for stdout.
	Path string `json:"path,omitempty"`
}

// Config is the gateway configuration.
type Config struct {
	// Listen is the bind address, e.g. "127.0.0.1:8385".
	Listen string `json:"listen,omitempty"`

	// PublicBaseURL is the externally visible base URL used in
	// generated .well-known metadata, e.g. "https://mcp.example.com"
	// behind a TLS-terminating proxy. When empty, metadata derives the
	// resource from the request Host with an http scheme.
	PublicBaseURL string `json:"public_base_url,omitempty"`

	// Audit configures the audit log destination.
	Audit AuditConfig `json:"audit,omitempty"`

	// Upstreams lists the MCP servers to route to. At least one is
	// required.
	Upstreams []Upstream `json:"upstreams"`
}

// Load reads and validates a JSON config file. Unknown fields are
// rejected so a typo fails loudly instead of silently disabling an
// option.
func Load(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the configuration and fills in defaults. It is
// called by Load and by New, so hand-built configs get the same
// treatment as loaded ones. It never touches the filesystem;
// lockfiles referenced by tools_lock are read when the gateway is
// built (or by LockInit).
func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.PublicBaseURL != "" {
		if err := validateHTTPURL(c.PublicBaseURL); err != nil {
			return fmt.Errorf("public_base_url: %w", err)
		}
	}
	if len(c.Upstreams) == 0 {
		return errors.New("at least one upstream is required")
	}
	seen := make(map[string]bool, len(c.Upstreams))
	for i, u := range c.Upstreams {
		if !nameRE.MatchString(u.Name) {
			return fmt.Errorf("upstream %d: name %q must match %s", i, u.Name, nameRE)
		}
		key := strings.ToLower(u.Name)
		if seen[key] {
			return fmt.Errorf("duplicate upstream name %q", u.Name)
		}
		seen[key] = true
		if err := validateHTTPURL(u.URL); err != nil {
			return fmt.Errorf("upstream %q: %w", u.Name, err)
		}
		if u.HeaderTimeoutSeconds < 0 {
			return fmt.Errorf("upstream %q: header_timeout_seconds must be >= 0", u.Name)
		}
		if u.RateLimit != nil {
			if u.RateLimit.RequestsPerSecond <= 0 {
				return fmt.Errorf("upstream %q: rate_limit.requests_per_second must be > 0", u.Name)
			}
			if u.RateLimit.Burst < 1 {
				return fmt.Errorf("upstream %q: rate_limit.burst must be >= 1", u.Name)
			}
		}
		if len(u.ToolsAllow) > 0 && len(u.ToolsDeny) > 0 {
			return fmt.Errorf("upstream %q: tools_allow and tools_deny are mutually exclusive", u.Name)
		}
		for _, tool := range u.ToolsAllow {
			if strings.TrimSpace(tool) == "" {
				return fmt.Errorf("upstream %q: tools_allow entries must not be empty", u.Name)
			}
		}
		for _, tool := range u.ToolsDeny {
			if strings.TrimSpace(tool) == "" {
				return fmt.Errorf("upstream %q: tools_deny entries must not be empty", u.Name)
			}
		}
		if u.ToolsLock != nil {
			if strings.TrimSpace(u.ToolsLock.File) == "" {
				return fmt.Errorf("upstream %q: tools_lock.file is required", u.Name)
			}
			switch u.ToolsLock.Mode {
			case "", "enforce", "warn":
			default:
				return fmt.Errorf("upstream %q: tools_lock.mode must be \"enforce\" or \"warn\", got %q", u.Name, u.ToolsLock.Mode)
			}
		}
		for _, as := range u.AuthorizationServers {
			if err := validateHTTPURL(as); err != nil {
				return fmt.Errorf("upstream %q: authorization server %q: %w", u.Name, as, err)
			}
		}
	}
	return nil
}

// validateHTTPURL checks that raw parses as an absolute http(s) URL
// without a query string or fragment.
func validateHTTPURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("url scheme must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return errors.New("url has no host")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("url must not contain a query string or fragment")
	}
	return nil
}

// ParseUpstreamFlag parses a --upstream flag value of the form
// "name=url".
func ParseUpstreamFlag(v string) (Upstream, error) {
	name, rawURL, ok := strings.Cut(v, "=")
	if !ok || name == "" || rawURL == "" {
		return Upstream{}, fmt.Errorf("upstream flag %q: want name=url", v)
	}
	return Upstream{Name: name, URL: rawURL}, nil
}
