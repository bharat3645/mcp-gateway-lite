package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bharat3645/mcp-gateway-lite/gateway"
)

func TestVersionFlag(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--version"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), gateway.Version) {
		t.Fatalf("version output = %q", out.String())
	}
}

func TestCheckValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := `{"listen":"127.0.0.1:0","upstreams":[{"name":"a","url":"http://127.0.0.1:1/mcp"}]}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"--config", path, "--check"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "config ok") {
		t.Fatalf("check output = %q", out.String())
	}
}

func TestCheckRejectsEmptyConfig(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--check"}, &out); err == nil {
		t.Fatal("expected error with no upstreams")
	}
}

func TestCheckWithUpstreamFlagOnly(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--upstream", "files=http://127.0.0.1:3001/mcp", "--check"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "upstreams=1") {
		t.Fatalf("check output = %q", out.String())
	}
}

func TestBadUpstreamFlag(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--upstream", "garbage", "--check"}, &out); err == nil {
		t.Fatal("expected error for malformed --upstream")
	}
}
