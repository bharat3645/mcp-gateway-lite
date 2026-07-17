package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// LockfileVersion is the mcp-sentinel lockfile format version the
// gateway reads and writes. The formats are interoperable: a lockfile
// written by `mcp-sentinel lock` (with a tools capture) can be
// enforced by the gateway, and a lockfile written by --lock-init can
// be verified offline by mcp-sentinel.
const LockfileVersion = 1

// lockFile is a sentinel-format lockfile. Server records stay raw so
// that merging preserves entries (and fields) written by other tools.
type lockFile struct {
	// LockfileVersion is the format version; must be 1.
	LockfileVersion int `json:"lockfileVersion"`

	// GeneratedBy records the writing tool, informational only.
	GeneratedBy string `json:"generatedBy,omitempty"`

	// Servers maps server name to its raw record.
	Servers map[string]json.RawMessage `json:"servers"`
}

// lockServer is one server record. Command/args/envKeys/entryHash are
// sentinel's config-fingerprint fields; a gateway-written record uses
// the empty fingerprint since the gateway does not launch servers.
type lockServer struct {
	// Command is the sentinel launch command (empty for
	// gateway-written records).
	Command string `json:"command"`

	// Args is the sentinel launch argument list.
	Args []string `json:"args"`

	// EnvKeys lists env var names (never values).
	EnvKeys []string `json:"envKeys"`

	// EntryHash is sentinel's config-entry fingerprint hash.
	EntryHash string `json:"entryHash,omitempty"`

	// ToolsHash is sentinel's whole-list tools digest; null when no
	// tools capture was recorded.
	ToolsHash *string `json:"toolsHash"`

	// URL is a gateway extension recording the upstream endpoint the
	// tools were fetched from.
	URL string `json:"url,omitempty"`

	// ToolsDetail is a gateway extension: per-tool fingerprint hashes
	// (name -> sha256:...). Per-tool verification keeps working when
	// servers paginate tools/list; sentinel ignores this field.
	ToolsDetail map[string]string `json:"toolsDetail,omitempty"`
}

// loadLockFile reads and validates a lockfile.
func loadLockFile(path string) (*lockFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lf lockFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("lockfile %s: %w", path, err)
	}
	if lf.Servers == nil {
		return nil, fmt.Errorf("lockfile %s: no servers table", path)
	}
	if lf.LockfileVersion != LockfileVersion {
		return nil, fmt.Errorf("lockfile %s: unsupported lockfileVersion %d (this build supports %d)", path, lf.LockfileVersion, LockfileVersion)
	}
	return &lf, nil
}

// writeLockFile writes a lockfile in sentinel style: indent 2, sorted
// keys, trailing newline, created 0600.
func writeLockFile(lf *lockFile, path string) error {
	doc := map[string]any{
		"lockfileVersion": lf.LockfileVersion,
		"generatedBy":     "mcp-gateway-lite " + Version,
		"servers":         lf.Servers,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

// rawTool is one tools/list element: its original bytes plus the
// drift-relevant surface.
type rawTool struct {
	// raw is the element exactly as the server sent it.
	raw json.RawMessage

	// name is the tool name ("" when absent).
	name string

	// hash is the sentinel-canonical fingerprint digest over
	// {name, description, inputSchema}.
	hash string
}

// toolFingerprint builds the sentinel-normalized form of one tool
// definition, accepting input_schema as a fallback spelling and
// defaulting missing fields exactly like sentinel's normalize_tools.
func toolFingerprint(raw json.RawMessage) (map[string]any, string, error) {
	var probe struct {
		Name           string          `json:"name"`
		Description    string          `json:"description"`
		InputSchema    json.RawMessage `json:"inputSchema"`
		InputSchemaAlt json.RawMessage `json:"input_schema"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, "", err
	}
	schemaRaw := probe.InputSchema
	if len(schemaRaw) == 0 {
		schemaRaw = probe.InputSchemaAlt
	}
	var schema any = map[string]any{}
	if len(schemaRaw) > 0 {
		v, err := decodeUseNumber(schemaRaw)
		if err != nil {
			return nil, "", err
		}
		schema = v
	}
	fp := map[string]any{
		"name":        probe.Name,
		"description": probe.Description,
		"inputSchema": schema,
	}
	return fp, probe.Name, nil
}

// parseLockTools decodes the elements of a tools array into rawTool
// values with sentinel-compatible fingerprint hashes.
func parseLockTools(elems []json.RawMessage) ([]rawTool, error) {
	tools := make([]rawTool, 0, len(elems))
	for _, el := range elems {
		fp, name, err := toolFingerprint(el)
		if err != nil {
			return nil, fmt.Errorf("tool entry unparseable: %w", err)
		}
		var buf bytes.Buffer
		if err := canonicalAppend(&buf, fp); err != nil {
			return nil, err
		}
		tools = append(tools, rawTool{raw: el, name: name, hash: sentinelHash(buf.Bytes())})
	}
	return tools, nil
}

// toolsListHash computes sentinel's tools_hash over a complete tool
// list: the canonical encoding of the fingerprints sorted by name.
func toolsListHash(elems []json.RawMessage) (string, error) {
	fps := make([]map[string]any, 0, len(elems))
	for _, el := range elems {
		fp, _, err := toolFingerprint(el)
		if err != nil {
			return "", err
		}
		fps = append(fps, fp)
	}
	sort.SliceStable(fps, func(i, j int) bool {
		a, _ := fps[i]["name"].(string)
		b, _ := fps[j]["name"].(string)
		return a < b
	})
	arr := make([]any, len(fps))
	for i, fp := range fps {
		arr[i] = fp
	}
	var buf bytes.Buffer
	if err := canonicalAppend(&buf, arr); err != nil {
		return "", err
	}
	return sentinelHash(buf.Bytes()), nil
}

// emptyEntryHash is the sentinel entryHash of a server entry with no
// command, args, or env — what gateway-written records use, since the
// gateway does not launch servers.
func emptyEntryHash() string {
	fp := map[string]any{
		"command": "",
		"args":    []any{},
		"envKeys": []any{},
	}
	var buf bytes.Buffer
	if err := canonicalAppend(&buf, fp); err != nil {
		return ""
	}
	return sentinelHash(buf.Bytes())
}

// preparedLock is a resolved tools_lock for one upstream, ready for
// inline verification.
type preparedLock struct {
	// file and server identify the lock entry, for error messages.
	file string

	// server is the lockfile server name backing this upstream.
	server string

	// enforce selects blocking (true) vs warn-only (false) handling
	// of drift.
	enforce bool

	// wholeHash is sentinel's toolsHash: a digest over the complete
	// sorted tool list. Used when no per-tool detail exists; a
	// partial (paginated) listing cannot match it, which is the
	// documented limitation of sentinel-written lockfiles.
	wholeHash string

	// detail maps tool name to fingerprint hash (the gateway's
	// toolsDetail extension). Preferred when present: per-tool
	// verification stays correct for paginated listings.
	detail map[string]string
}

// prepareLock resolves an upstream's tools_lock config against the
// lockfile(s), caching file reads across upstreams.
func prepareLock(u Upstream, cache map[string]*lockFile) (*preparedLock, error) {
	lc := u.ToolsLock
	if lc == nil {
		return nil, nil
	}
	lf, ok := cache[lc.File]
	if !ok {
		loaded, err := loadLockFile(lc.File)
		if err != nil {
			return nil, err
		}
		cache[lc.File] = loaded
		lf = loaded
	}
	server := lc.Server
	if server == "" {
		server = u.Name
	}
	raw, ok := lf.Servers[server]
	if !ok {
		return nil, fmt.Errorf("lockfile %s has no server %q (run --lock-init, or set tools_lock.server)", lc.File, server)
	}
	var rec lockServer
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("lockfile %s server %q: %w", lc.File, server, err)
	}
	if rec.ToolsHash == nil && len(rec.ToolsDetail) == 0 {
		return nil, fmt.Errorf("lockfile %s server %q has no tools capture (toolsHash is null) — re-lock with tools", lc.File, server)
	}
	pl := &preparedLock{
		file:    lc.File,
		server:  server,
		enforce: lc.Mode != "warn",
		detail:  rec.ToolsDetail,
	}
	if rec.ToolsHash != nil {
		pl.wholeHash = *rec.ToolsHash
	}
	return pl, nil
}

// verify checks a tools/list result against the lock. It returns ""
// when everything matches, or a drift description. With per-tool
// detail, every listed tool must match its locked fingerprint and
// unknown names are drift; with only a whole-list hash, the complete
// listing must reproduce the locked digest.
func (l *preparedLock) verify(elems []json.RawMessage) string {
	if len(l.detail) > 0 {
		tools, err := parseLockTools(elems)
		if err != nil {
			return "tools drift check failed: " + err.Error()
		}
		for _, tool := range tools {
			locked, ok := l.detail[tool.name]
			if !ok {
				return "tool not in lock: " + tool.name
			}
			if locked != tool.hash {
				return "tool schema drifted from lock: " + tool.name
			}
		}
		return ""
	}
	h, err := toolsListHash(elems)
	if err != nil {
		return "tools drift check failed: " + err.Error()
	}
	if h != l.wholeHash {
		return "tools/list drifted from locked hash (locked " + l.wholeHash + ", got " + h + ")"
	}
	return ""
}
