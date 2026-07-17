package gateway

import (
	"math"
	"sync"
	"time"
)

// tokenBucket is a minimal token-bucket rate limiter: continuous
// refill at rps tokens per second, capped at burst. A nil
// *tokenBucket means "no limit"; the zero value is not usable — build
// one with newTokenBucket.
type tokenBucket struct {
	mu sync.Mutex

	// rps is the sustained refill rate in tokens per second.
	rps float64

	// burst is the bucket capacity.
	burst float64

	// tokens is the current balance.
	tokens float64

	// last is when tokens was last refreshed.
	last time.Time

	// now is the clock, injectable for tests.
	now func() time.Time
}

func newTokenBucket(rps float64, burst int, now func() time.Time) *tokenBucket {
	if now == nil {
		now = time.Now
	}
	b := &tokenBucket{rps: rps, burst: float64(burst), now: now}
	b.tokens = b.burst
	b.last = now()
	return b
}

// allow consumes one token if available. When it returns false, retry
// reports how long until the next token exists.
func (b *tokenBucket) allow() (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.now()
	elapsed := t.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(b.burst, b.tokens+elapsed*b.rps)
		b.last = t
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	need := (1 - b.tokens) / b.rps
	return false, time.Duration(need * float64(time.Second))
}

// maxSessionBuckets bounds each upstream's per-session bucket table.
const maxSessionBuckets = 4096

// sessionLimiter keys token buckets by Mcp-Session-Id. Session ids
// are client-supplied, so this is a fairness mechanism between honest
// clients, not a hard defense: a client minting fresh ids gets fresh
// buckets. Memory is bounded; at capacity the least recently seen
// session is evicted (which also means an evicted-and-returning
// session gets a fresh burst — documented, and unavoidable for any
// bounded table keyed by untrusted ids).
type sessionLimiter struct {
	mu sync.Mutex

	// rps is the per-session sustained refill rate.
	rps float64

	// burst is the per-session bucket capacity.
	burst int

	// max bounds the bucket table size.
	max int

	// buckets maps session id to its bucket. Requests without a
	// session id share the "" bucket.
	buckets map[string]*tokenBucket

	// lastSeen tracks recency for eviction.
	lastSeen map[string]time.Time

	// now is the clock, injectable for tests.
	now func() time.Time
}

func newSessionLimiter(rps float64, burst, max int, now func() time.Time) *sessionLimiter {
	if now == nil {
		now = time.Now
	}
	if max < 1 {
		max = maxSessionBuckets
	}
	return &sessionLimiter{
		rps:      rps,
		burst:    burst,
		max:      max,
		buckets:  make(map[string]*tokenBucket),
		lastSeen: make(map[string]time.Time),
		now:      now,
	}
}

// allow consumes one token from the session's bucket, creating it
// (and evicting the least recently seen session at capacity) as
// needed.
func (l *sessionLimiter) allow(session string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[session]
	if !ok {
		if len(l.buckets) >= l.max {
			var oldest string
			var oldestT time.Time
			first := true
			for s, seen := range l.lastSeen {
				if first || seen.Before(oldestT) {
					oldest, oldestT, first = s, seen, false
				}
			}
			delete(l.buckets, oldest)
			delete(l.lastSeen, oldest)
		}
		b = newTokenBucket(l.rps, l.burst, l.now)
		l.buckets[session] = b
	}
	l.lastSeen[session] = l.now()
	return b.allow()
}
