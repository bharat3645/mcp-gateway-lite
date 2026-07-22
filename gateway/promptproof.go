package gateway

// This file embeds the `promptproof` data-plane scanner
// (https://github.com/bharat3645/promptproof) as inline middleware: it
// scans the untrusted content in tools/call *results* — the classic
// indirect / second-order prompt-injection path, where a compromised or
// hostile MCP server smuggles instructions or exfiltration lures back into
// the agent's context through what looks like an ordinary tool result.
//
// It does NOT reimplement any detection logic. It runs one (or a small
// pool of) `promptproof serve` coprocesses and streams content through
// them over promptproof's length-prefixed framing, parsing the JSON
// verdict promptproof already emits. Scanning is opt-in per upstream and
// off by default, so enabling it never silently changes existing behavior.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// promptProofBlockCode is the JSON-RPC error code returned when a
// tools/call result is blocked by promptproof (block action). It sits
// alongside the gateway's other policy codes (-32001..-32004).
const promptProofBlockCode = -32005

// defaultScanTimeout bounds a single coprocess scan. promptproof scans a
// few-KB tool result in microseconds; this only guards against a hung or
// wedged coprocess never answering, so a request cannot block forever.
const defaultScanTimeout = 5 * time.Second

// defaultScanPool is the number of warm coprocesses per scanning upstream.
const defaultScanPool = 2

// verdictRank orders promptproof's verdicts so a threshold comparison is a
// simple >=. Unknown strings rank 0 (treated as ok / below any threshold).
func verdictRank(v string) int {
	switch v {
	case "suspicious":
		return 1
	case "dangerous":
		return 2
	default:
		return 0
	}
}

// scanResult is the metadata this gateway keeps from a promptproof report:
// the verdict, the aggregate score, and the finding categories (for the
// audit log). Never the matched content — the audit trail is metadata-only.
type scanResult struct {
	Verdict    string
	Score      int
	Categories []string
}

// ppReport is the subset of promptproof's JSON report we decode.
type ppReport struct {
	Verdict  string `json:"verdict"`
	Score    int    `json:"score"`
	Findings []struct {
		Category string `json:"category"`
	} `json:"findings"`
}

// Scanner runs a pool of `promptproof serve` coprocesses and scans content
// through them. It is safe for concurrent use: each Scan checks a
// coprocess out of a channel, so at most poolSize scans run at once and
// each coprocess speaks to one caller at a time.
type Scanner struct {
	bin       string
	args      []string
	threshold int // verdictRank at or above which Action fires
	action    string
	timeout   time.Duration
	pool      chan *ppProc

	closeOnce sync.Once
}

// newScanner builds a Scanner from a validated PromptProofConfig. It spawns
// the coprocess pool eagerly so a misconfigured binary fails at startup,
// not on the first scanned request.
func newScanner(c *PromptProofConfig) (*Scanner, error) {
	bin := c.Binary
	if bin == "" {
		bin = "promptproof"
	}
	args := []string{"serve"}
	if c.SuspiciousAt > 0 {
		args = append(args, "--suspicious-at", strconv.Itoa(c.SuspiciousAt))
	}
	if c.DangerousAt > 0 {
		args = append(args, "--dangerous-at", strconv.Itoa(c.DangerousAt))
	}
	threshold := verdictRank(c.Threshold)
	if threshold == 0 {
		threshold = verdictRank("dangerous") // default: only dangerous fires
	}
	action := c.Action
	if action == "" {
		action = "block"
	}
	size := c.Pool
	if size <= 0 {
		size = defaultScanPool
	}

	s := &Scanner{
		bin:       bin,
		args:      args,
		threshold: threshold,
		action:    action,
		timeout:   defaultScanTimeout,
		pool:      make(chan *ppProc, size),
	}
	for i := 0; i < size; i++ {
		p := &ppProc{bin: bin, args: args}
		if err := p.ensure(); err != nil {
			s.Close()
			return nil, fmt.Errorf("promptproof: starting %q: %w", bin, err)
		}
		s.pool <- p
	}
	return s, nil
}

// Scan scans content and returns the verdict. On a coprocess error it
// returns the error (callers fail open — see scanMessage): a scanner that
// cannot answer must not take the whole gateway down.
func (s *Scanner) Scan(content string) (scanResult, error) {
	p := <-s.pool
	res, err := p.scan(content, s.timeout)
	s.pool <- p
	return res, err
}

// triggers reports whether a verdict is at or above the configured
// threshold.
func (s *Scanner) triggers(verdict string) bool {
	return verdictRank(verdict) >= s.threshold
}

// Close shuts every coprocess down. Safe to call more than once.
func (s *Scanner) Close() {
	s.closeOnce.Do(func() {
		close(s.pool)
		for p := range s.pool {
			p.shutdown()
		}
	})
}

// ppProc is one `promptproof serve` coprocess. A ppProc is only ever
// touched by one goroutine at a time (the pool hands it out exclusively).
type ppProc struct {
	bin  string
	args []string

	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdoutR io.ReadCloser
	stdout  *bufio.Reader
}

// ensure (re)starts the coprocess if it is not currently running. Uses
// plain os.Pipe rather than cmd.StdoutPipe/StdinPipe so cmd.Wait during a
// kill never races a pending read on a Wait-managed pipe.
func (p *ppProc) ensure() error {
	if p.cmd != nil {
		return nil
	}
	cmd := exec.Command(p.bin, p.args...)
	inR, inW, err := os.Pipe()
	if err != nil {
		return err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return err
	}
	cmd.Stdin = inR
	cmd.Stdout = outW
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return err
	}
	// The child owns its ends now; drop the parent's copies so EOF
	// propagates correctly.
	inR.Close()
	outW.Close()
	p.cmd = cmd
	p.stdin = inW
	p.stdoutR = outR
	p.stdout = bufio.NewReader(outR)
	return nil
}

// scan writes one length-prefixed frame and reads one JSON verdict line,
// bounded by timeout. On any I/O error or timeout it kills the coprocess
// (so the next scan respawns it) and returns the error.
func (p *ppProc) scan(content string, timeout time.Duration) (scanResult, error) {
	if err := p.ensure(); err != nil {
		return scanResult{}, err
	}
	// Capture handles locally: if a timeout kills and respawns the
	// coprocess, a lingering goroutine must touch only the old (closed)
	// pipes, never the fresh ones.
	stdin, stdout := p.stdin, p.stdout

	type ioResult struct {
		line string
		err  error
	}
	ch := make(chan ioResult, 1)
	go func() {
		header := strconv.Itoa(len(content)) + "\n"
		if _, err := io.WriteString(stdin, header); err != nil {
			ch <- ioResult{err: err}
			return
		}
		if _, err := io.WriteString(stdin, content); err != nil {
			ch <- ioResult{err: err}
			return
		}
		line, err := stdout.ReadString('\n')
		ch <- ioResult{line: line, err: err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			p.kill()
			return scanResult{}, fmt.Errorf("promptproof scan I/O: %w", r.err)
		}
		return parseReport(r.line)
	case <-time.After(timeout):
		p.kill()
		return scanResult{}, fmt.Errorf("promptproof scan timed out after %s", timeout)
	}
}

// kill terminates the coprocess and marks it for respawn on next use.
func (p *ppProc) kill() {
	if p.cmd == nil {
		return
	}
	if p.stdin != nil {
		p.stdin.Close()
	}
	if p.stdoutR != nil {
		p.stdoutR.Close()
	}
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
	p.cmd = nil
	p.stdin = nil
	p.stdoutR = nil
	p.stdout = nil
}

// shutdown closes stdin (serve exits 0 on EOF) and reaps the process.
func (p *ppProc) shutdown() {
	if p.cmd == nil {
		return
	}
	if p.stdin != nil {
		p.stdin.Close()
	}
	_ = p.cmd.Wait()
	if p.stdoutR != nil {
		p.stdoutR.Close()
	}
	p.cmd = nil
}

// parseReport decodes one promptproof JSON report line into a scanResult.
func parseReport(line string) (scanResult, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return scanResult{}, fmt.Errorf("promptproof: empty response")
	}
	var rep ppReport
	if err := json.Unmarshal([]byte(line), &rep); err != nil {
		return scanResult{}, fmt.Errorf("promptproof: bad response %q: %w", line, err)
	}
	res := scanResult{Verdict: rep.Verdict, Score: rep.Score}
	seen := make(map[string]bool, len(rep.Findings))
	for _, f := range rep.Findings {
		if f.Category != "" && !seen[f.Category] {
			seen[f.Category] = true
			res.Categories = append(res.Categories, f.Category)
		}
	}
	return res, nil
}

// collectStrings walks a JSON value and appends every string *value* it
// contains (object values and array elements, recursively; object keys are
// structural and skipped). Decoding to Go strings turns any JSON-escaped
// hidden characters (e.g. "​") back into the real code points, so
// promptproof sees the covert channel the raw bytes would have hidden.
func collectStrings(raw json.RawMessage, out *[]string) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		*out = append(*out, s)
		return
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, e := range arr {
			collectStrings(e, out)
		}
		return
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		for _, e := range obj {
			collectStrings(e, out)
		}
		return
	}
	// numbers, booleans, null: nothing to scan.
}
