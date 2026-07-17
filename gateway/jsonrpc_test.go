package gateway

import "testing"

func TestSummarizeSingleRequest(t *testing.T) {
	s := summarizeRPC([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if s.Invalid || s.Batch {
		t.Fatalf("summary = %+v", s)
	}
	if len(s.Methods) != 1 || s.Methods[0] != "tools/list" {
		t.Errorf("methods = %v", s.Methods)
	}
	if len(s.IDs) != 1 || s.IDs[0] != "1" {
		t.Errorf("ids = %v", s.IDs)
	}
}

func TestSummarizeNotification(t *testing.T) {
	s := summarizeRPC([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if len(s.Methods) != 1 || s.Methods[0] != "notifications/initialized" {
		t.Errorf("methods = %v", s.Methods)
	}
	if len(s.IDs) != 0 {
		t.Errorf("ids = %v, want none for a notification", s.IDs)
	}
}

func TestSummarizeToolCall(t *testing.T) {
	s := summarizeRPC([]byte(`{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"search","arguments":{"q":"x"}}}`))
	if len(s.Tools) != 1 || s.Tools[0] != "search" {
		t.Errorf("tools = %v", s.Tools)
	}
	if len(s.IDs) != 1 || s.IDs[0] != `"abc"` {
		t.Errorf("ids = %v (string ids keep their JSON quoting)", s.IDs)
	}
}

func TestSummarizeBatch(t *testing.T) {
	s := summarizeRPC([]byte(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch"}}]`))
	if !s.Batch {
		t.Error("expected batch")
	}
	if len(s.Methods) != 2 || s.Methods[0] != "ping" || s.Methods[1] != "tools/call" {
		t.Errorf("methods = %v", s.Methods)
	}
	if len(s.Tools) != 1 || s.Tools[0] != "fetch" {
		t.Errorf("tools = %v", s.Tools)
	}
}

func TestSummarizeClientResponseMessage(t *testing.T) {
	s := summarizeRPC([]byte(`{"jsonrpc":"2.0","id":9,"result":{"ok":true}}`))
	if s.Invalid {
		t.Error("client-to-server response messages are valid Streamable HTTP POSTs")
	}
	if len(s.Methods) != 0 {
		t.Errorf("methods = %v", s.Methods)
	}
	if len(s.IDs) != 1 || s.IDs[0] != "9" {
		t.Errorf("ids = %v", s.IDs)
	}
}

func TestSummarizePositionalParams(t *testing.T) {
	s := summarizeRPC([]byte(`{"jsonrpc":"2.0","id":1,"method":"custom/op","params":[1,2,3]}`))
	if s.Invalid {
		t.Error("positional params must not be treated as invalid")
	}
	if len(s.Methods) != 1 || s.Methods[0] != "custom/op" {
		t.Errorf("methods = %v", s.Methods)
	}
	if len(s.Tools) != 0 {
		t.Errorf("tools = %v", s.Tools)
	}
}

func TestSummarizeInvalidBodies(t *testing.T) {
	for _, body := range []string{"not json", "42", `"str"`, "[", "[]"} {
		s := summarizeRPC([]byte(body))
		if !s.Invalid {
			t.Errorf("summarizeRPC(%q).Invalid = false, want true", body)
		}
	}
}

func TestSummarizeEmptyBody(t *testing.T) {
	s := summarizeRPC(nil)
	if s.Invalid || len(s.Methods) != 0 || len(s.IDs) != 0 {
		t.Errorf("summary = %+v", s)
	}
}

func TestSummarizeNullID(t *testing.T) {
	s := summarizeRPC([]byte(`{"jsonrpc":"2.0","id":null,"method":"ping"}`))
	if len(s.IDs) != 0 {
		t.Errorf("ids = %v, want none for null id", s.IDs)
	}
	if len(s.Methods) != 1 || s.Methods[0] != "ping" {
		t.Errorf("methods = %v", s.Methods)
	}
}
