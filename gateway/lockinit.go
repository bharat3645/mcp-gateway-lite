package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// lockProtocolVersion is the MCP protocol version the lock-init
// client advertises.
const lockProtocolVersion = "2025-06-18"

// maxLockPages bounds tools/list pagination during lock-init.
const maxLockPages = 100

// LockInit connects to every configured upstream, fetches its full
// tools/list (following pagination), and writes — or merges into — a
// sentinel-format lockfile at path: toolsHash (whole-list digest,
// verifiable offline by mcp-sentinel) plus toolsDetail (per-tool
// digests, the gateway extension that keeps inline verification
// working when servers paginate). Records for servers not managed by
// the gateway are preserved.
func LockInit(cfg Config, path string, out io.Writer) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	existing := &lockFile{LockfileVersion: LockfileVersion, Servers: map[string]json.RawMessage{}}
	if _, err := os.Stat(path); err == nil {
		loaded, err := loadLockFile(path)
		if err != nil {
			return fmt.Errorf("refusing to overwrite unrecognized lockfile: %w", err)
		}
		existing = loaded
	}
	client := &http.Client{Timeout: 15 * time.Second}
	for _, u := range cfg.Upstreams {
		elems, err := fetchAllTools(client, u.URL)
		if err != nil {
			return fmt.Errorf("upstream %q: %w", u.Name, err)
		}
		tools, err := parseLockTools(elems)
		if err != nil {
			return fmt.Errorf("upstream %q: %w", u.Name, err)
		}
		detail := make(map[string]string, len(tools))
		for _, tool := range tools {
			if tool.name == "" {
				return fmt.Errorf("upstream %q: tools/list entry without a name", u.Name)
			}
			if _, dup := detail[tool.name]; dup {
				return fmt.Errorf("upstream %q: duplicate tool name %q", u.Name, tool.name)
			}
			detail[tool.name] = tool.hash
		}
		whole, err := toolsListHash(elems)
		if err != nil {
			return fmt.Errorf("upstream %q: %w", u.Name, err)
		}
		rec := lockServer{
			Command:     "",
			Args:        []string{},
			EnvKeys:     []string{},
			EntryHash:   emptyEntryHash(),
			ToolsHash:   &whole,
			URL:         u.URL,
			ToolsDetail: detail,
		}
		encoded, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		existing.Servers[u.Name] = encoded
		fmt.Fprintf(out, "locked %s: %d tools (%s)\n", u.Name, len(tools), whole)
	}
	if err := writeLockFile(existing, path); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s\n", path)
	return nil
}

// fetchAllTools performs the minimal MCP handshake (initialize,
// notifications/initialized) and pages through tools/list.
func fetchAllTools(client *http.Client, baseURL string) ([]json.RawMessage, error) {
	initParams := fmt.Sprintf(`{"protocolVersion":%q,"capabilities":{},"clientInfo":{"name":"mcp-gateway-lite","version":%q}}`, lockProtocolVersion, Version)
	_, hdr, err := doRPC(client, baseURL, "", "initialize", json.RawMessage(initParams), 1)
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	session := hdr.Get("Mcp-Session-Id")
	notifyInitialized(client, baseURL, session)

	var all []json.RawMessage
	cursor := ""
	for page := 0; page < maxLockPages; page++ {
		params := json.RawMessage(`{}`)
		if cursor != "" {
			p, err := json.Marshal(map[string]string{"cursor": cursor})
			if err != nil {
				return nil, err
			}
			params = p
		}
		result, _, err := doRPC(client, baseURL, session, "tools/list", params, page+2)
		if err != nil {
			return nil, fmt.Errorf("tools/list: %w", err)
		}
		var lst struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}
		if err := json.Unmarshal(result, &lst); err != nil {
			return nil, fmt.Errorf("tools/list result: %w", err)
		}
		if lst.Tools == nil {
			return nil, errors.New("tools/list result has no tools array")
		}
		all = append(all, lst.Tools...)
		if lst.NextCursor == "" {
			return all, nil
		}
		cursor = lst.NextCursor
	}
	return nil, errors.New("tools/list pagination exceeded the page limit")
}

// notifyInitialized sends notifications/initialized. Failures are
// ignored: stateless servers do not need it.
func notifyInitialized(client *http.Client, baseURL, session string) {
	req, err := http.NewRequest(http.MethodPost, baseURL, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", lockProtocolVersion)
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
}

// doRPC posts one JSON-RPC request and decodes the response, which
// may arrive as application/json or as an SSE stream carrying the
// response message.
func doRPC(client *http.Client, baseURL, session, method string, params json.RawMessage, id int) (json.RawMessage, http.Header, error) {
	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if len(params) > 0 {
		msg["params"] = params
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", lockProtocolVersion)
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRPCPeek))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, nil, fmt.Errorf("%s: HTTP %d: %s", method, resp.StatusCode, truncateForError(data))
	}
	payload := data
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		payload = firstSSEResponse(data)
		if payload == nil {
			return nil, nil, fmt.Errorf("%s: no JSON-RPC response found in SSE stream", method)
		}
	}
	var rpc struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(payload, &rpc); err != nil {
		return nil, nil, fmt.Errorf("%s: response not parseable: %w", method, err)
	}
	if len(rpc.Error) > 0 && string(rpc.Error) != "null" {
		return nil, nil, fmt.Errorf("%s: JSON-RPC error: %s", method, truncateForError(rpc.Error))
	}
	if len(rpc.Result) == 0 {
		return nil, nil, fmt.Errorf("%s: response has no result", method)
	}
	return rpc.Result, resp.Header, nil
}

// truncateForError keeps error messages readable.
func truncateForError(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}

// firstSSEResponse scans a complete SSE payload for the first event
// whose data parses as a JSON-RPC response (result or error).
func firstSSEResponse(data []byte) json.RawMessage {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	for _, chunk := range bytes.Split(data, []byte("\n\n")) {
		var payload []byte
		for _, line := range bytes.Split(chunk, []byte("\n")) {
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			v := line[5:]
			if len(v) > 0 && v[0] == ' ' {
				v = v[1:]
			}
			if len(payload) > 0 {
				payload = append(payload, '\n')
			}
			payload = append(payload, v...)
		}
		if len(payload) == 0 {
			continue
		}
		var probe struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(payload, &probe); err == nil && (len(probe.Result) > 0 || len(probe.Error) > 0) {
			return payload
		}
	}
	return nil
}
