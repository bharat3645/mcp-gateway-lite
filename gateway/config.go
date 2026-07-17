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
// treatment as loaded ones.
func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
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
		parsed, err := url.Parse(u.URL)
		if err != nil {
			return fmt.Errorf("upstream %q: invalid url: %w", u.Name, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("upstream %q: url scheme must be http or https, got %q", u.Name, parsed.Scheme)
		}
		if parsed.Host == "" {
			return fmt.Errorf("upstream %q: url has no host", u.Name)
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("upstream %q: url must not contain a query string or fragment", u.Name)
		}
		if u.HeaderTimeoutSeconds < 0 {
			return fmt.Errorf("upstream %q: header_timeout_seconds must be >= 0", u.Name)
		}
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
