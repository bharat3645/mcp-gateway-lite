package gateway

import (
	"bytes"
	"encoding/json"
	"testing"
)

// The vectors in this file were generated with the REAL mcp-sentinel
// lockfile code (mcp_sentinel/lockfile.py: _canonical, _sha256,
// tools_hash, entry_hash), so the Go canonicalizer is pinned to
// Python's actual behavior rather than to a mental model of it.

func TestCanonicalMatchesPythonVectors(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		canonical string
		hash      string
	}{
		{
			"simple tool fingerprint",
			`{"name": "read_file", "description": "Read a file from disk", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}`,
			`{"description":"Read a file from disk","inputSchema":{"properties":{"path":{"type":"string"}},"required":["path"],"type":"object"},"name":"read_file"}`,
			"sha256:ec3d9d36dff46ea919f752177ca15373a1eb5f72793f13b2565b5de40872676c",
		},
		{
			"unicode escapes",
			`{"name": "café", "description": "Zoëké 🔧 tool 𝄞 漢字", "inputSchema": {}}`,
			`{"description":"Zoëké 🔧 tool 𝄞 漢字","inputSchema":{},"name":"café"}`,
			"sha256:a43e1f8e875a6666f5f7a6180232bbf2bb8183dbdc8d3ea8c0cc5bf0ba4498b8",
		},
		{
			"control chars",
			`{"name": "x", "description": "line1\nline2\ttab\rcr\bbs\fff\"quote\\backslashunitdel", "inputSchema": {}}`,
			`{"description":"line1\nline2\ttab\rcr\bbs\fff\"quote\\backslashunitdel","inputSchema":{},"name":"x"}`,
			"sha256:d823b7265ffe7ea9c5ed2ec5e88997771aff787bc4095f3905a69d5d99d061da",
		},
		{
			"numbers",
			`{"name": "n", "description": "", "inputSchema": {"minimum": 0, "maximum": 100, "big": 12345678901234567890, "neg": -7, "half": 0.5, "onepointfive": 1.5}}`,
			`{"description":"","inputSchema":{"big":12345678901234567890,"half":0.5,"maximum":100,"minimum":0,"neg":-7,"onepointfive":1.5},"name":"n"}`,
			"sha256:ba092be26f6b7faac3d2e723eae7a449cca20e1eda4fa5a153f287f619a868b6",
		},
		{
			"nested",
			`{"name": "z", "description": "", "inputSchema": {"a": [1, {"b": [true, false, null, []], "a": {}}, "s"], "empty": {}}}`,
			`{"description":"","inputSchema":{"a":[1,{"a":{},"b":[true,false,null,[]]},"s"],"empty":{}},"name":"z"}`,
			"sha256:1be242abffa2559d062dbcba0507d976ddd703f73d04699800fa098da3d8d968",
		},
	}
	for _, tc := range cases {
		v, err := decodeUseNumber([]byte(tc.input))
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		var buf bytes.Buffer
		if err := canonicalAppend(&buf, v); err != nil {
			t.Fatalf("%s: canonical: %v", tc.name, err)
		}
		if got := buf.String(); got != tc.canonical {
			t.Errorf("%s: canonical =\n %s\nwant\n %s", tc.name, got, tc.canonical)
		}
		if got := sentinelHash(buf.Bytes()); got != tc.hash {
			t.Errorf("%s: hash = %s, want %s", tc.name, got, tc.hash)
		}
	}
}

// vectorTools matches the tool set hashed by the Python vector
// generator (and served by ci/upstream_stub.py, so the CI smoke can
// cross-check against a real mcp-sentinel checkout).
var vectorTools = []string{
	`{"name":"search","description":"Search things","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}`,
	`{"name":"delete_file","description":"Delete a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}`,
	`{"name":"read_file","description":"Read a file from disk","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}`,
}

// vectorToolsListHash is sentinel's tools_hash over vectorTools.
const vectorToolsListHash = "sha256:6d63f327606d2b9dc386a8718bde320c753c653cf49edefe427c3281c2da617e"

// toolElems turns JSON tool documents into raw list elements.
func toolElems(t *testing.T, docs []string) []json.RawMessage {
	t.Helper()
	elems := make([]json.RawMessage, len(docs))
	for i, d := range docs {
		elems[i] = json.RawMessage(d)
	}
	return elems
}

func TestToolsHashesMatchSentinel(t *testing.T) {
	elems := toolElems(t, vectorTools)
	h, err := toolsListHash(elems)
	if err != nil {
		t.Fatal(err)
	}
	if h != vectorToolsListHash {
		t.Errorf("tools list hash = %s, want %s", h, vectorToolsListHash)
	}
	// Order-insensitive: reversed input, same digest.
	rev := toolElems(t, []string{vectorTools[2], vectorTools[1], vectorTools[0]})
	h2, err := toolsListHash(rev)
	if err != nil {
		t.Fatal(err)
	}
	if h2 != vectorToolsListHash {
		t.Errorf("reversed tools list hash = %s, want %s", h2, vectorToolsListHash)
	}
	// Per-tool fingerprint hashes (the toolsDetail extension).
	tools, err := parseLockTools(elems)
	if err != nil {
		t.Fatal(err)
	}
	wantDetail := map[string]string{
		"search":      "sha256:c88f35dddce36091b6b6f8b65f79a98dabfb332ad49eb614d7e5ce58a6df5017",
		"delete_file": "sha256:ef9cbbb6408eabeb9b355e8d6c9943154e89a00111b427e6f0e1ac36134da3a9",
		"read_file":   "sha256:ec3d9d36dff46ea919f752177ca15373a1eb5f72793f13b2565b5de40872676c",
	}
	if len(tools) != 3 {
		t.Fatalf("tools = %d", len(tools))
	}
	for _, tool := range tools {
		if wantDetail[tool.name] != tool.hash {
			t.Errorf("tool %s hash = %s, want %s", tool.name, tool.hash, wantDetail[tool.name])
		}
	}
}

func TestSnakeCaseSchemaAndDefaults(t *testing.T) {
	tools, err := parseLockTools([]json.RawMessage{json.RawMessage(`{"name":"snake","input_schema":{"type":"object"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:e112c61bea4edfc9ed4cab9c1aaae89b8aaec7835d07af2d5de504f11650d541"
	if tools[0].hash != want {
		t.Errorf("snake tool hash = %s, want %s", tools[0].hash, want)
	}
}

func TestEmptyEntryHashMatchesSentinel(t *testing.T) {
	const want = "sha256:a70d268c811ce84d86639a41958f2b208df10b7868c9902333dae9a65a259a88"
	if got := emptyEntryHash(); got != want {
		t.Errorf("emptyEntryHash = %s, want %s", got, want)
	}
}
