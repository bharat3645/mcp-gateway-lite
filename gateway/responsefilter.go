package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// rewriteState carries one request's tools/list response-processing
// context from handleProxy into the proxy's ModifyResponse hook (and
// the SSE rewriter), and the outcome back out to the audit entry. It
// is only ever touched from the request's own handler goroutine.
type rewriteState struct {
	// ids holds the raw JSON-RPC id literals of the tools/list
	// requests found in the inbound body. Only response messages
	// carrying one of these ids are candidates for filtering; results
	// for other ids are someone else's data and pass untouched.
	ids []string

	// policy is the upstream's tool policy, applied to tools/list
	// results so clients never see tools they cannot call. nil means
	// no filtering.
	policy *toolPolicy

	// lock is the upstream's prepared tools_lock; tools/list results
	// are verified against it before any filtering. nil means no
	// verification.
	lock *preparedLock

	// strict selects fail-closed handling for responses the gateway
	// cannot process (allowlist or enforce-lock semantics: a check
	// that fails open is theater). Otherwise the state runs lax: what
	// cannot be processed passes through, because a deny list (or a
	// warn-mode lock) is best-effort by nature.
	strict bool

	// filtered counts tools removed from tools/list results.
	filtered int

	// drift reports that lock verification failed at least once.
	drift bool

	// note records the first noteworthy processing outcome for the
	// audit entry.
	note string

	// scanner scans tools/call result content for prompt-injection /
	// exfiltration signals. nil means no scanning for this request.
	scanner *Scanner

	// scanIDs holds the raw ids of this request's tools/call messages;
	// only responses to these are scanned.
	scanIDs []string

	// scanVerdict is the worst verdict seen, scanScore/scanCategories the
	// accompanying metadata, for the audit entry.
	scanVerdict    string
	scanScore      int
	scanCategories []string

	// scanBlocked reports that at least one tools/call result was
	// replaced with a -32005 error. scanFlagged reports a triggering
	// verdict under the flag action (passed through, audited).
	scanBlocked bool
	scanFlagged bool

	// scanErr records the first scanner failure (fail-open: the result
	// still passes through).
	scanErr string
}

// noteOnce records the first noteworthy processing outcome.
func (st *rewriteState) noteOnce(reason string) {
	if st.note == "" {
		st.note = reason
	}
}

// strictCode is the JSON-RPC error code used when strict processing
// replaces a response: -32003 when the strictness comes from an
// allowlist policy, -32004 when it comes from an enforce-mode lock.
func (st *rewriteState) strictCode() int {
	if st.policy != nil && st.policy.allow != nil {
		return -32003
	}
	if st.lock != nil && st.lock.enforce {
		return -32004
	}
	return -32003
}

// hasID reports whether raw is the id of one of the request's
// tools/list messages. Ids are compared as raw JSON literals, so
// string ids keep their quoting on both sides.
func (st *rewriteState) hasID(raw []byte) bool {
	for _, id := range st.ids {
		if id == string(raw) {
			return true
		}
	}
	return false
}

// hasScanID reports whether raw is the id of one of the request's
// tools/call messages (whose result should be scanned by promptproof).
func (st *rewriteState) hasScanID(raw []byte) bool {
	for _, id := range st.scanIDs {
		if id == string(raw) {
			return true
		}
	}
	return false
}

// handleMessage routes one JSON-RPC response message to the right
// processing pass by its id: a tools/list result is verified/filtered
// (examineMessage); a tools/call result is scanned (scanMessage). A
// message that matches neither passes untouched. The two id sets are
// disjoint (different requests), so a message goes to at most one pass.
func (st *rewriteState) handleMessage(m json.RawMessage) msgOutcome {
	if st.scanner != nil && len(st.scanIDs) > 0 {
		var probe struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(m, &probe); err == nil && len(probe.ID) > 0 && st.hasScanID(probe.ID) {
			return st.scanMessage(m)
		}
	}
	return st.examineMessage(m)
}

// scanMessage scans the untrusted content of one tools/call result. On a
// triggering verdict it either blocks (replaces the result with a -32005
// JSON-RPC error) or flags (passes through, records metadata + sets a
// response header via the caller). A scanner failure fails open: the
// result passes through and the error is audited — a scanner that cannot
// answer must not silently drop legitimate tool output.
func (st *rewriteState) scanMessage(m json.RawMessage) msgOutcome {
	var probe rpcResponseProbe
	if err := json.Unmarshal(m, &probe); err != nil {
		return msgOutcome{verdict: msgPass, invalid: true}
	}
	if len(probe.Error) > 0 && string(probe.Error) != "null" {
		// An error response carries no tool output to trust.
		return msgOutcome{verdict: msgPass}
	}
	if len(probe.Result) == 0 {
		return msgOutcome{verdict: msgPass}
	}
	var strs []string
	collectStrings(probe.Result, &strs)
	content := strings.Join(strs, "\n")

	res, err := st.scanner.Scan(content)
	if err != nil {
		if st.scanErr == "" {
			st.scanErr = err.Error()
		}
		st.noteOnce("promptproof scan error: " + err.Error())
		return msgOutcome{verdict: msgPass}
	}
	st.recordScan(res)

	if !st.scanner.triggers(res.Verdict) {
		return msgOutcome{verdict: msgPass}
	}
	if st.scanner.action == "flag" {
		st.scanFlagged = true
		return msgOutcome{verdict: msgPass}
	}
	st.scanBlocked = true
	reason := fmt.Sprintf("tool result blocked by promptproof: %s (score %d)", res.Verdict, res.Score)
	st.noteOnce(reason)
	return msgOutcome{verdict: msgBlock, id: probe.ID, code: promptProofBlockCode, reason: reason}
}

// recordScan folds one scan result into the request's worst-verdict
// metadata for the audit entry. Clean (ok) results add nothing — the audit
// only carries a promptproof verdict when there was something to report.
func (st *rewriteState) recordScan(res scanResult) {
	if verdictRank(res.Verdict) == 0 {
		return
	}
	if verdictRank(res.Verdict) > verdictRank(st.scanVerdict) {
		st.scanVerdict = res.Verdict
		st.scanScore = res.Score
	}
	for _, c := range res.Categories {
		if !containsString(st.scanCategories, c) {
			st.scanCategories = append(st.scanCategories, c)
		}
	}
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// msgVerdict classifies the outcome of examining one JSON-RPC
// response message.
type msgVerdict int

const (
	// msgPass means the original bytes go through untouched.
	msgPass msgVerdict = iota

	// msgRewrite means out replaces the message: tools were filtered.
	msgRewrite

	// msgBlock means strict processing refuses the message.
	msgBlock
)

// msgOutcome is the result of examineMessage.
type msgOutcome struct {
	verdict msgVerdict

	// out is the replacement message for msgRewrite.
	out json.RawMessage

	// id is the raw id of a blocked message, so the JSON-RPC error
	// can be correlated by the client. May be empty.
	id json.RawMessage

	// code is the JSON-RPC error code for msgBlock.
	code int

	// reason says why the message was blocked.
	reason string

	// invalid reports that the bytes were not a JSON object at all.
	// The SSE path passes such events through verbatim (they are
	// inert to a JSON-RPC client); the JSON path blocks them in
	// strict mode.
	invalid bool
}

// rpcResponseProbe decodes only the response-message fields the
// rewriter needs. Result content stays raw so untouched fields are
// re-emitted byte-exact.
type rpcResponseProbe struct {
	JSONRPC json.RawMessage `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

// examineMessage inspects one JSON-RPC response message.
// Non-candidate messages (other ids, error responses) pass. For a
// candidate tools/list result it verifies the lock, then applies the
// tool policy, dropping blocked tools; kept tools and sibling result
// fields are emitted with their original bytes.
func (st *rewriteState) examineMessage(m json.RawMessage) msgOutcome {
	var probe rpcResponseProbe
	if err := json.Unmarshal(m, &probe); err != nil {
		return msgOutcome{verdict: msgPass, invalid: true}
	}
	if len(probe.ID) == 0 || !st.hasID(probe.ID) {
		return msgOutcome{verdict: msgPass}
	}
	if len(probe.Error) > 0 && string(probe.Error) != "null" {
		// An error response to tools/list carries no tool
		// definitions; nothing to verify or filter.
		return msgOutcome{verdict: msgPass}
	}
	block := func(reason string) msgOutcome {
		return msgOutcome{verdict: msgBlock, id: probe.ID, code: st.strictCode(), reason: reason}
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(probe.Result, &result); err != nil || result == nil {
		if st.strict {
			return block("tools/list result is not an object")
		}
		return msgOutcome{verdict: msgPass}
	}
	toolsRaw, ok := result["tools"]
	if !ok {
		if st.strict {
			return block("tools/list result has no tools array")
		}
		return msgOutcome{verdict: msgPass}
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(toolsRaw, &elems); err != nil {
		if st.strict {
			return block("tools/list result tools is not an array")
		}
		return msgOutcome{verdict: msgPass}
	}
	// Lock verification runs before policy filtering, against the
	// tools exactly as the server sent them — the lock pins server
	// truth; the filter shapes the client's view.
	if st.lock != nil {
		if reason := st.lock.verify(elems); reason != "" {
			st.drift = true
			st.noteOnce(reason)
			if st.lock.enforce {
				return msgOutcome{verdict: msgBlock, id: probe.ID, code: -32004, reason: reason}
			}
		}
	}
	kept := make([]json.RawMessage, 0, len(elems))
	removed := 0
	for _, el := range elems {
		var tp struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(el, &tp); err != nil || tp.Name == "" {
			if st.strict {
				return block("tools/list entry without a tool name")
			}
			kept = append(kept, el)
			continue
		}
		if st.policy.allows(tp.Name) {
			kept = append(kept, el)
		} else {
			removed++
		}
	}
	if removed == 0 {
		return msgOutcome{verdict: msgPass}
	}
	st.filtered += removed
	newTools, err := json.Marshal(kept)
	if err != nil {
		return block("tools/list result could not be rebuilt")
	}
	result["tools"] = newTools
	newResult, err := json.Marshal(result)
	if err != nil {
		return block("tools/list result could not be rebuilt")
	}
	var out bytes.Buffer
	out.WriteString(`{"jsonrpc":`)
	if len(probe.JSONRPC) > 0 {
		out.Write(probe.JSONRPC)
	} else {
		out.WriteString(`"2.0"`)
	}
	out.WriteString(`,"id":`)
	out.Write(probe.ID)
	out.WriteString(`,"result":`)
	out.Write(newResult)
	out.WriteByte('}')
	return msgOutcome{verdict: msgRewrite, out: out.Bytes()}
}

// modifyResponse is installed on every upstream proxy. It does
// nothing unless handleProxy attached a rewriteState for this request
// (the request contained tools/list and the upstream has something to
// enforce on the way back).
func modifyResponse(resp *http.Response) error {
	st, _ := resp.Request.Context().Value(rewriteKey).(*rewriteState)
	if st == nil {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		// Non-200 responses carry no accepted tool definitions.
		return nil
	}
	ct := resp.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "application/json"):
		err := st.processJSONBody(resp)
		// flag action: the result passed through; annotate the response so
		// a client can see the verdict without parsing the audit log. (SSE
		// scans mid-stream, after headers are sent, so it cannot do this —
		// the audit entry is the record there.)
		if st.scanFlagged && st.scanVerdict != "" {
			resp.Header.Set("X-PromptProof-Verdict", st.scanVerdict)
		}
		return err
	case strings.HasPrefix(ct, "text/event-stream"):
		resp.Body = newSSERewriter(resp.Body, st)
		// Rewriting can change event sizes; the stream has no usable
		// length anyway.
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
		return nil
	default:
		if st.strict {
			st.blockResponse(resp, "tools/list response has unexpected content type "+strconv.Quote(ct))
		}
		return nil
	}
}

// processJSONBody verifies and filters an application/json response
// to a request that contained tools/list. Batches are all-or-nothing
// on strict failures, matching request-side policy semantics.
func (st *rewriteState) processJSONBody(resp *http.Response) error {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(resp.Body, maxRPCPeek+1)); err != nil {
		return err
	}
	if buf.Len() > maxRPCPeek {
		if st.strict {
			st.blockResponse(resp, "tools/list response exceeded the processing cap")
			return nil
		}
		// Lax: splice the buffered prefix back onto the unread rest
		// and pass the response through untouched.
		resp.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(buf.Bytes()), resp.Body), Closer: resp.Body}
		return nil
	}
	body := bytes.TrimSpace(buf.Bytes())
	var out []byte
	switch {
	case len(body) == 0:
		// Empty body: nothing to inspect.
	case body[0] == '[':
		var msgs []json.RawMessage
		if err := json.Unmarshal(body, &msgs); err != nil {
			if st.strict {
				st.blockResponse(resp, "tools/list response is not parseable JSON")
				return nil
			}
			break
		}
		changed := false
		outMsgs := make([]json.RawMessage, len(msgs))
		for i, m := range msgs {
			o := st.handleMessage(m)
			switch o.verdict {
			case msgBlock:
				st.blockResponseCode(resp, o.code, o.reason)
				return nil
			case msgRewrite:
				outMsgs[i] = o.out
				changed = true
			default:
				if o.invalid && st.strict {
					st.blockResponse(resp, "tools/list response batch entry is not an object")
					return nil
				}
				outMsgs[i] = m
			}
		}
		if changed {
			joined, err := json.Marshal(outMsgs)
			if err != nil {
				return err
			}
			out = joined
		}
	default:
		o := st.handleMessage(json.RawMessage(body))
		switch o.verdict {
		case msgBlock:
			st.blockResponseCode(resp, o.code, o.reason)
			return nil
		case msgRewrite:
			out = o.out
		default:
			if o.invalid && st.strict {
				st.blockResponse(resp, "tools/list response is not parseable JSON")
				return nil
			}
		}
	}
	if out == nil {
		// Nothing changed: hand back exactly the bytes the upstream
		// sent.
		resp.Body = readCloser{Reader: bytes.NewReader(buf.Bytes()), Closer: resp.Body}
		return nil
	}
	swapBody(resp, http.StatusOK, out)
	return nil
}

// blockResponse replaces resp with a 403 JSON-RPC error carrying the
// strict-mode error code.
func (st *rewriteState) blockResponse(resp *http.Response, reason string) {
	st.blockResponseCode(resp, st.strictCode(), reason)
}

// blockResponseCode replaces resp with a 403 JSON-RPC error.
func (st *rewriteState) blockResponseCode(resp *http.Response, code int, reason string) {
	st.noteOnce(reason)
	swapBody(resp, http.StatusForbidden, append(jsonrpcError(nil, code, reason), '\n'))
}

// swapBody replaces a response's status and body, fixing the headers
// the replacement invalidates.
func swapBody(resp *http.Response, status int, body []byte) {
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.StatusCode = status
	resp.Status = fmt.Sprintf("%d %s", status, http.StatusText(status))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Del("Content-Encoding")
	resp.TransferEncoding = nil
}

// jsonrpcError renders a JSON-RPC error message. The message string
// is encoded with encoding/json so arbitrary reason text (tool names,
// header values) cannot produce invalid JSON.
func jsonrpcError(id json.RawMessage, code int, msg string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	encoded, err := json.Marshal(msg)
	if err != nil {
		encoded = []byte(`"internal error"`)
	}
	var b bytes.Buffer
	b.WriteString(`{"jsonrpc":"2.0","id":`)
	b.Write(id)
	b.WriteString(`,"error":{"code":`)
	b.WriteString(strconv.Itoa(code))
	b.WriteString(`,"message":`)
	b.Write(encoded)
	b.WriteString(`}}`)
	return b.Bytes()
}
