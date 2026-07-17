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
