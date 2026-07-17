package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAuditorWritesJSONLines(t *testing.T) {
	buf := &syncBuffer{}
	a := NewAuditorWriter(buf)
	var e Entry
	e.Time = now()
	e.Upstream = "files"
	e.HTTPMethod = "POST"
	e.Path = "/mcp/files"
	e.Status = 200
	a.Log(e)

	line := strings.TrimSpace(buf.String())
	var got Entry
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("line %q: %v", line, err)
	}
	if got.Upstream != "files" || got.Status != 200 {
		t.Errorf("got = %+v", got)
	}
	if !strings.Contains(line, "\"ts\":") {
		t.Errorf("line missing ts: %q", line)
	}
}

func TestAuditorConcurrentLineIntegrity(t *testing.T) {
	buf := &syncBuffer{}
	a := NewAuditorWriter(buf)
	const workers = 8
	const perWorker = 50
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				var e Entry
				e.Time = now()
				e.Upstream = fmt.Sprintf("w%d", id)
				e.Status = 200
				a.Log(e)
			}
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != workers*perWorker {
		t.Fatalf("lines = %d, want %d", len(lines), workers*perWorker)
	}
	for _, line := range lines {
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("corrupt line %q: %v", line, err)
		}
	}
}

func TestAuditorFileSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := NewAuditor(AuditConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	var e Entry
	e.Time = now()
	e.Upstream = "x"
	a.Log(e)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\"upstream\":\"x\"") {
		t.Fatalf("file = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
}

func TestAuditorFileSinkAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for i := 0; i < 2; i++ {
		a, err := NewAuditor(AuditConfig{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		var e Entry
		e.Time = now()
		a.Log(e)
		a.Close()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Split(strings.TrimSpace(string(data)), "\n")); n != 2 {
		t.Errorf("lines = %d, want 2 (append semantics)", n)
	}
}

type failWriter struct{}

func (failWriter) Write(p []byte) (int, error) {
	return 0, errors.New("sink failed")
}

func TestAuditorSinkFailureDoesNotPanic(t *testing.T) {
	a := NewAuditorWriter(failWriter{})
	var e Entry
	e.Time = now()
	a.Log(e)
	a.Log(e)
}
