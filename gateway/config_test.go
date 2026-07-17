package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValidConfig(t *testing.T) {
	path := writeConfig(t, `{
		"listen": "127.0.0.1:9000",
		"audit": {"path": "audit.jsonl"},
		"upstreams": [
			{"name": "files", "url": "http://127.0.0.1:3001/mcp"},
			{"name": "search", "url": "https://mcp.example.com/mcp", "header_timeout_seconds": 60}
		]
	}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9000" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.Audit.Path != "audit.jsonl" {
		t.Errorf("audit path = %q", cfg.Audit.Path)
	}
	if len(cfg.Upstreams) != 2 {
		t.Fatalf("upstreams = %d", len(cfg.Upstreams))
	}
	if cfg.Upstreams[1].HeaderTimeoutSeconds != 60 {
		t.Errorf("timeout = %d", cfg.Upstreams[1].HeaderTimeoutSeconds)
	}
}

func TestLoadDefaultsListen(t *testing.T) {
	path := writeConfig(t, `{"upstreams":[{"name":"a","url":"http://h/mcp"}]}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen {
		t.Errorf("listen = %q, want %q", cfg.Listen, DefaultListen)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := writeConfig(t, `{"listne":"x","upstreams":[{"name":"a","url":"http://h/mcp"}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no upstreams", Config{}},
		{"bad name", Config{Upstreams: []Upstream{{Name: "-bad", URL: "http://h/mcp"}}}},
		{"empty name", Config{Upstreams: []Upstream{{Name: "", URL: "http://h/mcp"}}}},
		{"dup names case-insensitive", Config{Upstreams: []Upstream{{Name: "a", URL: "http://h/mcp"}, {Name: "A", URL: "http://h/mcp"}}}},
		{"bad scheme", Config{Upstreams: []Upstream{{Name: "a", URL: "ftp://h/mcp"}}}},
		{"no host", Config{Upstreams: []Upstream{{Name: "a", URL: "http:///mcp"}}}},
		{"query string", Config{Upstreams: []Upstream{{Name: "a", URL: "http://h/mcp?x=1"}}}},
		{"negative timeout", Config{Upstreams: []Upstream{{Name: "a", URL: "http://h/mcp", HeaderTimeoutSeconds: -1}}}},
	}
	for _, tc := range cases {
		cfg := tc.cfg
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestValidateFillsDefaults(t *testing.T) {
	cfg := Config{Upstreams: []Upstream{{Name: "a", URL: "http://h/mcp"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen {
		t.Errorf("listen = %q, want %q", cfg.Listen, DefaultListen)
	}
}

func TestParseUpstreamFlag(t *testing.T) {
	u, err := ParseUpstreamFlag("files=http://127.0.0.1:3001/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "files" || u.URL != "http://127.0.0.1:3001/mcp" {
		t.Errorf("u = %+v", u)
	}
	for _, bad := range []string{"", "noequals", "=url", "name="} {
		if _, err := ParseUpstreamFlag(bad); err == nil {
			t.Errorf("ParseUpstreamFlag(%q): expected error", bad)
		}
	}
}
