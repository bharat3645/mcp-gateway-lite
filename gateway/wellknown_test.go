package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newWellKnownGateway(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	gw, err := New(cfg, NewAuditorWriter(&syncBuffer{}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)
	return srv
}

func TestWellKnownMetadata(t *testing.T) {
	upstream := echoUpstream(t)
	u := Upstream{Name: "files", URL: upstream.URL}
	u.AuthorizationServers = []string{"https://auth.example.com"}
	u.ResourceName = "Files MCP"
	srv := newWellKnownGateway(t, Config{Upstreams: []Upstream{u}})

	resp, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource/mcp/files")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var md map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		t.Fatal(err)
	}
	if got, want := md["resource"], srv.URL+"/mcp/files"; got != want {
		t.Errorf("resource = %v, want %v", got, want)
	}
	auth, _ := md["authorization_servers"].([]any)
	if len(auth) != 1 || auth[0] != "https://auth.example.com" {
		t.Errorf("authorization_servers = %v", md["authorization_servers"])
	}
	bm, _ := md["bearer_methods_supported"].([]any)
	if len(bm) != 1 || bm[0] != "header" {
		t.Errorf("bearer_methods_supported = %v", md["bearer_methods_supported"])
	}
	if md["resource_name"] != "Files MCP" {
		t.Errorf("resource_name = %v", md["resource_name"])
	}
}

func TestWellKnownUsesPublicBaseURL(t *testing.T) {
	upstream := echoUpstream(t)
	cfg := Config{PublicBaseURL: "https://mcp.example.com/", Upstreams: []Upstream{{Name: "files", URL: upstream.URL}}}
	srv := newWellKnownGateway(t, cfg)

	resp, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource/mcp/files")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var md map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		t.Fatal(err)
	}
	if got, want := md["resource"], "https://mcp.example.com/mcp/files"; got != want {
		t.Errorf("resource = %v, want %v", got, want)
	}
}

func TestWellKnownUnknownUpstream(t *testing.T) {
	upstream := echoUpstream(t)
	srv := newWellKnownGateway(t, Config{Upstreams: []Upstream{{Name: "files", URL: upstream.URL}}})

	for _, path := range []string{
		"/.well-known/oauth-protected-resource/mcp/nope",
		"/.well-known/oauth-protected-resource/mcp/files/extra",
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestLoadConfigWithM2Fields(t *testing.T) {
	path := writeConfig(t, `{
		"public_base_url": "https://mcp.example.com",
		"upstreams": [
			{
				"name": "files",
				"url": "http://127.0.0.1:3001/mcp",
				"rate_limit": {"requests_per_second": 5, "burst": 10},
				"authorization_servers": ["https://auth.example.com"],
				"resource_name": "Files"
			}
		]
	}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	u := cfg.Upstreams[0]
	if u.RateLimit == nil || u.RateLimit.RequestsPerSecond != 5 || u.RateLimit.Burst != 10 {
		t.Errorf("rate limit = %+v", u.RateLimit)
	}
	if cfg.PublicBaseURL != "https://mcp.example.com" {
		t.Errorf("public_base_url = %q", cfg.PublicBaseURL)
	}
}

func TestValidateM2Errors(t *testing.T) {
	good := "http://h/mcp"
	cases := []struct {
		name string
		cfg  Config
	}{
		{"zero rps", Config{Upstreams: []Upstream{{Name: "a", URL: good, RateLimit: &RateLimitConfig{RequestsPerSecond: 0, Burst: 1}}}}},
		{"negative rps", Config{Upstreams: []Upstream{{Name: "a", URL: good, RateLimit: &RateLimitConfig{RequestsPerSecond: -1, Burst: 1}}}}},
		{"zero burst", Config{Upstreams: []Upstream{{Name: "a", URL: good, RateLimit: &RateLimitConfig{RequestsPerSecond: 1, Burst: 0}}}}},
		{"bad auth server", Config{Upstreams: []Upstream{{Name: "a", URL: good, AuthorizationServers: []string{"ftp://x"}}}}},
		{"bad public base url", Config{PublicBaseURL: "not a url", Upstreams: []Upstream{{Name: "a", URL: good}}}},
		{"public base url with query", Config{PublicBaseURL: "https://h?x=1", Upstreams: []Upstream{{Name: "a", URL: good}}}},
	}
	for _, tc := range cases {
		cfg := tc.cfg
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}
