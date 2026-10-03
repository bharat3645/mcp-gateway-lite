package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// This file implements the canonical JSON form used by mcp-sentinel
// lockfiles — Python's json.dumps with sort_keys=True,
// separators=(",", ":"), ensure_ascii=True — so tool-schema hashes
// computed by either tool agree byte-for-byte. The Go implementation
// is pinned to the Python behavior by golden vectors generated with
// the real mcp-sentinel code (see canonical_test.go).
//
// One deliberate divergence: JSON number literals are emitted exactly
// as they appear in the source document, while Python normalizes
// them (1e2 -> 100.0). For tool schemas, whose numbers are almost
// always plain integers, the encodings agree; when they do not, the
// failure mode is a spurious drift alarm, never a false match.
//
// A second, non-deliberate divergence exists at the decode step, not
// here: Go's encoding/json silently collapses both invalid UTF-8
// bytes and unpaired UTF-16 surrogate escapes (e.g. a lone "\ud800"
// with no following low surrogate) into U+FFFD, while Python's
// json.loads either preserves an unpaired surrogate as a distinct
// code point or raises UnicodeDecodeError outright for invalid UTF-8.
// Two inputs that differ only in which invalid byte or surrogate they
// contain can therefore decode to the identical Go string and hash
// identically here, while sentinel would treat them as different (or
// reject one outright) — a silent hash collision in the one place
// this file exists to prevent. errReplacementChar below closes that
// by refusing to canonicalize (and therefore to hash) any string
// containing U+FFFD at all, including a string that happens to
// genuinely intend that code point: this tool has no way to tell the
// two cases apart post-decode, and in a drift-detection primitive a
// loud refusal is the correct failure mode, not a silent false match.
// See TestCanonicalRejectsReplacementChar.

// errReplacementChar is returned by canonicalAppend for any string
// containing U+FFFD, since such a string cannot be canonicalized with
// a guaranteed-accurate parity with mcp-sentinel's Python decoder.
var errReplacementChar = errors.New("canonical: string contains U+FFFD (invalid UTF-8 or an unpaired surrogate escape); cannot guarantee a hash matching mcp-sentinel")

// decodeUseNumber decodes one JSON value, preserving number literals.
func decodeUseNumber(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

// canonicalAppend appends the canonical encoding of v (a value from
// decodeUseNumber) to dst.
func canonicalAppend(dst *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		dst.WriteString("null")
	case bool:
		if t {
			dst.WriteString("true")
		} else {
			dst.WriteString("false")
		}
	case json.Number:
		dst.WriteString(t.String())
	case string:
		if strings.ContainsRune(t, utf8.RuneError) {
			return errReplacementChar
		}
		appendPythonString(dst, t)
	case []any:
		dst.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				dst.WriteByte(',')
			}
			if err := canonicalAppend(dst, el); err != nil {
				return err
			}
		}
		dst.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// Bytewise order equals code-point order in UTF-8, which is
		// what Python's sort_keys produces.
		sort.Strings(keys)
		dst.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				dst.WriteByte(',')
			}
			if strings.ContainsRune(k, utf8.RuneError) {
				return errReplacementChar
			}
			appendPythonString(dst, k)
			dst.WriteByte(':')
			if err := canonicalAppend(dst, t[k]); err != nil {
				return err
			}
		}
		dst.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
	return nil
}

// appendPythonString appends s escaped the way Python's json module
// does with ensure_ascii=True: printable ASCII (0x20..0x7e) literal
// except quote and backslash, short escapes for the usual control
// characters, \uXXXX (lowercase hex) for everything else, and
// surrogate pairs for astral code points.
func appendPythonString(dst *bytes.Buffer, s string) {
	dst.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			dst.WriteString(`\"`)
		case '\\':
			dst.WriteString(`\\`)
		case '\n':
			dst.WriteString(`\n`)
		case '\r':
			dst.WriteString(`\r`)
		case '\t':
			dst.WriteString(`\t`)
		case '\b':
			dst.WriteString(`\b`)
		case '\f':
			dst.WriteString(`\f`)
		default:
			switch {
			case r >= 0x20 && r <= 0x7e:
				dst.WriteByte(byte(r))
			case r <= 0xffff:
				fmt.Fprintf(dst, `\u%04x`, r)
			default:
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(dst, `\u%04x\u%04x`, hi, lo)
			}
		}
	}
	dst.WriteByte('"')
}

// sentinelHash renders the "sha256:<hex>" digest of a canonical
// encoding, matching mcp-sentinel's _sha256.
func sentinelHash(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}
