package gateway

import (
	"bytes"
	"io"
)

// sseRewriter transforms a text/event-stream response body, rewriting
// only complete events that carry a tools/list result for one of the
// request's tools/list ids. Everything else — comments, keepalives,
// other fields, other messages, even unparseable event data — passes
// through byte-verbatim, because a JSON-RPC client cannot extract
// tools from an event its own parser rejects.
//
// The state machine was validated against exhaustive chunk-boundary
// tests: every split of the fixture streams must produce identical
// output. Events are emitted as soon as their terminating blank line
// arrives, so mid-stream delivery (and flushing) is preserved.
//
// Oversized events (beyond maxRPCPeek) cannot be buffered for
// inspection. In strict mode the event is replaced with a JSON-RPC
// error and discarded to its boundary; in lax mode it streams through
// verbatim. Either way the stream continues afterwards.
type sseRewriter struct {
	src io.ReadCloser

	st *rewriteState

	// out accumulates processed bytes ready for Read.
	out bytes.Buffer

	// line assembles a partial line until its terminator arrives.
	line []byte

	// evLines holds the completed lines of the current event, raw
	// bytes including terminators. evIsData marks which of them are
	// data lines; evData holds the corresponding payloads with the
	// "data:" prefix and optional leading space stripped.
	evLines  [][]byte
	evIsData []bool
	evData   [][]byte

	// evSize tracks the byte size of the current event.
	evSize int

	// raw streams bytes through verbatim until the next event
	// boundary (lax oversize handling). discard drops them instead
	// (strict oversize handling). bstate is the boundary detector: 0
	// scanning, 1 saw \n, 2 saw \n\r.
	raw     bool
	discard bool
	bstate  int

	chunk   []byte
	srcErr  error
	srcDone bool
}

// newSSERewriter wraps an SSE response body.
func newSSERewriter(src io.ReadCloser, st *rewriteState) *sseRewriter {
	return &sseRewriter{src: src, st: st, chunk: make([]byte, 32*1024)}
}

// Read implements io.Reader. It never blocks on the source while
// processed output is pending, so events flow to the client as they
// complete.
func (r *sseRewriter) Read(p []byte) (int, error) {
	for r.out.Len() == 0 && !r.srcDone {
		n, err := r.src.Read(r.chunk)
		if n > 0 {
			r.ingest(r.chunk[:n])
		}
		if err != nil {
			r.srcDone = true
			r.srcErr = err
			r.finish()
		}
	}
	if r.out.Len() > 0 {
		return r.out.Read(p)
	}
	return 0, r.srcErr
}

// Close implements io.Closer.
func (r *sseRewriter) Close() error {
	return r.src.Close()
}

// ingest feeds a chunk of source bytes through the state machine.
func (r *sseRewriter) ingest(b []byte) {
	for len(b) > 0 {
		if r.raw || r.discard {
			b = r.scanBoundary(b)
			continue
		}
		j := bytes.IndexByte(b, '\n')
		if j < 0 {
			r.line = append(r.line, b...)
			if len(r.line)+r.evSize > maxRPCPeek {
				r.overflowPartial()
			}
			return
		}
		r.line = append(r.line, b[:j+1]...)
		b = b[j+1:]
		line := r.line
		r.line = nil
		r.completeLine(line)
	}
}

// scanBoundary consumes bytes in raw/discard mode until an event
// boundary (\n\n or \n\r\n), returning the unconsumed remainder.
func (r *sseRewriter) scanBoundary(b []byte) []byte {
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch r.bstate {
		case 0:
			if c == '\n' {
				r.bstate = 1
			}
		case 1:
			switch c {
			case '\n':
				if r.raw {
					r.out.Write(b[:i+1])
				}
				r.raw, r.discard, r.bstate = false, false, 0
				return b[i+1:]
			case '\r':
				r.bstate = 2
			default:
				r.bstate = 0
			}
		case 2:
			if c == '\n' {
				if r.raw {
					r.out.Write(b[:i+1])
				}
				r.raw, r.discard, r.bstate = false, false, 0
				return b[i+1:]
			}
			r.bstate = 0
		}
	}
	if r.raw {
		r.out.Write(b)
	}
	return nil
}

// overflowPartial handles an event exceeding the processing cap while
// a line is still unterminated.
func (r *sseRewriter) overflowPartial() {
	pending := r.line
	r.line = nil
	if r.st.strict {
		r.emitCapError()
		r.discard = true
	} else {
		for _, l := range r.evLines {
			r.out.Write(l)
		}
		r.out.Write(pending)
		r.raw = true
	}
	r.bstate = 0
	r.resetEvent()
}

// overflowLine handles a completed line pushing the event over the
// processing cap.
func (r *sseRewriter) overflowLine(l []byte) {
	if r.st.strict {
		r.emitCapError()
		r.discard = true
	} else {
		for _, ln := range r.evLines {
			r.out.Write(ln)
		}
		r.out.Write(l)
		r.raw = true
	}
	// The line ended with \n, so the boundary detector starts one
	// newline in.
	r.bstate = 1
	r.resetEvent()
}

// emitCapError emits a JSON-RPC error event for an event the strict
// mode could not inspect.
func (r *sseRewriter) emitCapError() {
	const reason = "tools/list SSE event exceeded the processing cap"
	r.st.noteOnce(reason)
	r.out.WriteString("data: ")
	r.out.Write(jsonrpcError(nil, r.st.strictCode(), reason))
	r.out.WriteString("\n\n")
}

// completeLine processes one line, terminator included.
func (r *sseRewriter) completeLine(l []byte) {
	stripped := trimEOL(l)
	if len(stripped) == 0 {
		r.finishEvent(l)
		return
	}
	r.evSize += len(l)
	if r.evSize > maxRPCPeek {
		r.overflowLine(l)
		return
	}
	isData := bytes.HasPrefix(stripped, []byte("data:"))
	r.evLines = append(r.evLines, l)
	r.evIsData = append(r.evIsData, isData)
	if isData {
		v := stripped[5:]
		if len(v) > 0 && v[0] == ' ' {
			v = v[1:]
		}
		r.evData = append(r.evData, v)
	}
}

// trimEOL strips one trailing \n and one preceding \r.
func trimEOL(l []byte) []byte {
	l = bytes.TrimSuffix(l, []byte("\n"))
	return bytes.TrimSuffix(l, []byte("\r"))
}

// finishEvent handles a complete event; blank is the terminating
// blank line, preserved byte-exact on passthrough.
func (r *sseRewriter) finishEvent(blank []byte) {
	if len(r.evData) == 0 {
		for _, l := range r.evLines {
			r.out.Write(l)
		}
		r.out.Write(blank)
		r.resetEvent()
		return
	}
	data := bytes.Join(r.evData, []byte("\n"))
	o := r.st.examineMessage(data)
	switch o.verdict {
	case msgRewrite:
		r.emitReplaced(o.out, blank)
	case msgBlock:
		r.st.noteOnce(o.reason)
		r.emitReplaced(jsonrpcError(o.id, o.code, o.reason), blank)
	default:
		for _, l := range r.evLines {
			r.out.Write(l)
		}
		r.out.Write(blank)
	}
	r.resetEvent()
}

// emitReplaced re-emits the current event with its data lines
// replaced by a single new payload. Non-data lines (event:, id:,
// comments) are preserved in their original order and bytes.
func (r *sseRewriter) emitReplaced(payload []byte, blank []byte) {
	for i, l := range r.evLines {
		if !r.evIsData[i] {
			r.out.Write(l)
		}
	}
	r.out.WriteString("data: ")
	r.out.Write(payload)
	r.out.WriteByte('\n')
	r.out.Write(blank)
}

// resetEvent clears the current event buffers.
func (r *sseRewriter) resetEvent() {
	r.evLines = nil
	r.evIsData = nil
	r.evData = nil
	r.evSize = 0
}

// finish flushes any partial event and line verbatim at end of
// stream. A partial event cannot be dispatched by an SSE client, so
// passing it through carries no tools/list risk in either mode.
func (r *sseRewriter) finish() {
	if r.raw || r.discard {
		// raw already streamed everything; discard drops by design.
		return
	}
	for _, l := range r.evLines {
		r.out.Write(l)
	}
	r.out.Write(r.line)
	r.line = nil
	r.resetEvent()
}
