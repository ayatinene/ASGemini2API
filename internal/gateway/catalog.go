package gateway

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ayatinene/ASGemini2API/internal/aicode"
	"google.golang.org/grpc/codes"
)

const defaultReadTimeout = 65 * time.Second

type snapshot[T any] struct {
	FetchedAt time.Time
	Value     T
}

type cacheCall[T any] struct {
	done    chan struct{}
	epoch   uint64
	cancel  context.CancelFunc
	waiters int
	aborted bool
	value   snapshot[T]
	err     error
}

type cache[T any] struct {
	mu       sync.Mutex
	epoch    uint64
	value    snapshot[T]
	ttl      time.Duration
	timeout  time.Duration
	pending  *cacheCall[T]
	failed   error
	retryAt  time.Time
	load     func(context.Context) (T, error)
	cooldown func(error) time.Duration
}

func (c *cache[T]) latest() snapshot[T] {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value
}

func (c *cache[T]) get(ctx context.Context, fresh bool) (snapshot[T], error) {
	if err := ctx.Err(); err != nil {
		return snapshot[T]{}, err
	}

	c.mu.Lock()
	if !fresh && !c.value.FetchedAt.IsZero() && time.Since(c.value.FetchedAt) < c.ttl {
		val := c.value
		c.mu.Unlock()
		return val, nil
	}
	if time.Now().Before(c.retryAt) {
		err := c.failed
		c.mu.Unlock()
		return snapshot[T]{}, err
	}
	call := c.pending
	if call == nil {
		timeout := c.timeout
		if timeout <= 0 {
			timeout = defaultReadTimeout
		}
		loadCtx, cancel := context.WithTimeout(context.Background(), timeout)
		call = &cacheCall[T]{
			done:   make(chan struct{}),
			cancel: cancel,
			epoch:  c.epoch,
		}
		c.pending = call
		go c.run(call, loadCtx)
	}
	call.waiters++
	c.mu.Unlock()

	select {
	case <-call.done:
		c.mu.Lock()
		call.waiters--
		c.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return snapshot[T]{}, err
		}
		if call.err != nil {
			return snapshot[T]{}, call.err
		}
		return call.value, nil
	case <-ctx.Done():
		c.mu.Lock()
		call.waiters--
		if call.waiters == 0 && c.pending == call {
			call.aborted = true
			call.cancel()
			c.pending = nil
		}
		c.mu.Unlock()
		return snapshot[T]{}, ctx.Err()
	}
}

func (c *cache[T]) run(call *cacheCall[T], loadCtx context.Context) {
	defer call.cancel()
	value, err := c.load(loadCtx)
	if err == nil {
		err = loadCtx.Err()
	}

	c.mu.Lock()
	if c.pending == call {
		c.pending = nil
	}
	if err == nil && !call.aborted {
		snap := snapshot[T]{FetchedAt: time.Now().UTC(), Value: value}
		call.value = snap
		if call.epoch == c.epoch {
			c.value = snap
			c.failed = nil
			c.retryAt = time.Time{}
		}
	} else {
		if err == nil {
			err = loadCtx.Err()
		}
		call.err = err
		if call.epoch == c.epoch && !call.aborted && !errors.Is(loadCtx.Err(), context.Canceled) {
			c.failed = err
			cd := c.cooldown
			if cd == nil {
				cd = readCooldown
			}
			if d := cd(err); d > 0 {
				c.retryAt = time.Now().Add(d)
			}
		}
	}
	close(call.done)
	c.mu.Unlock()
}

// reset drops cached values after the active Google account changes. An
// in-flight fetch is detached so its result is delivered to its waiters but
// never committed to the new account's cache.
func (c *cache[T]) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch++
	c.value = snapshot[T]{}
	c.failed = nil
	c.retryAt = time.Time{}
	c.pending = nil
}

func readCooldown(err error) time.Duration {
	var upstream *aicode.Error
	if errors.As(err, &upstream) {
		if upstream.RetryAfter > 0 {
			return upstream.RetryAfter
		}
		switch upstream.Code {
		case codes.ResourceExhausted:
			return 30 * time.Second
		case codes.PermissionDenied:
			return 15 * time.Second
		}
	}
	return 2 * time.Second
}
