// Copyright Honeycomb
// SPDX-License-Identifier: Apache-2.0

// Package authcache caches /1/auth validation results with separate positive
// and negative TTLs. It uses github.com/hashicorp/golang-lru/v2 (the LRU library
// standard across the Collector and contrib) for bounded eviction, and expires
// entries lazily on read (the base LRU has no background goroutine, so there is
// nothing to stop on Shutdown). Concurrent misses for the same key are collapsed
// with a singleflight so a burst of first-time requests makes only one upstream
// call.
//
// Expired positive entries are kept for a stale window: if revalidation fails
// with a transient error (auth backend unreachable), the last known-good result
// is served instead, so an /1/auth outage does not take down established
// traffic. Invalid-key verdicts are never served stale.
package authcache // import "github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension/internal/authcache"

import (
	"errors"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sync/singleflight"

	"github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension/internal/hnyauth"
)

type entry struct {
	info    *hnyauth.AuthInfo // nil when invalid
	invalid bool
	// stale marks an entry whose last revalidation failed transiently and is
	// being served from the stale window.
	stale bool
	// refreshAt is when the entry must be revalidated upstream.
	refreshAt time.Time
	// validatedAt is when the loader last succeeded; it anchors the stale
	// window, which deliberately does not slide while the backend is down.
	validatedAt time.Time
}

type lookupState int

const (
	stateMissing lookupState = iota
	stateFresh
	stateStale // positive entry past refreshAt but within the stale window
)

// Cache holds positive (valid AuthInfo) and negative (invalid key) results.
type Cache struct {
	lru      *lru.Cache[string, entry]
	ttl      time.Duration
	negTTL   time.Duration
	staleTTL time.Duration
	sf       singleflight.Group
	now      func() time.Time // overridable in tests
}

// New builds a cache bounded to maxKeys entries, with ttl for positive results
// and negTTL for negative results. staleTTL is how long past a successful
// validation a positive result may still be served when revalidation fails
// transiently; 0 disables stale serving.
func New(maxKeys int, ttl, negTTL, staleTTL time.Duration) (*Cache, error) {
	l, err := lru.New[string, entry](maxKeys)
	if err != nil {
		return nil, err
	}
	return &Cache{
		lru:      l,
		ttl:      ttl,
		negTTL:   negTTL,
		staleTTL: staleTTL,
		now:      time.Now,
	}, nil
}

func (c *Cache) lookup(key string) (entry, lookupState) {
	e, ok := c.lru.Get(key)
	if !ok {
		return entry{}, stateMissing
	}
	now := c.now()
	if now.Before(e.refreshAt) {
		return e, stateFresh
	}
	if e.invalid || now.After(e.validatedAt.Add(c.staleTTL)) {
		c.lru.Remove(key)
		return entry{}, stateMissing
	}
	return e, stateStale
}

type resolved struct {
	info  *hnyauth.AuthInfo
	stale bool
}

// Resolve returns the cached result for key, or calls loader exactly once (per
// concurrent set of callers) on a miss. A returned hnyauth.ErrInvalidKey is
// cached negatively; any other loader error is NOT cached (so transient
// auth-backend failures don't stick), but falls back to a stale positive entry
// when one is within its stale window - the returned bool reports that
// fallback. key should be a digest of the API key (raw digest bytes as a
// string are fine), never the key itself.
func (c *Cache) Resolve(key string, loader func() (*hnyauth.AuthInfo, error)) (*hnyauth.AuthInfo, bool, error) {
	if e, st := c.lookup(key); st == stateFresh {
		if e.invalid {
			return nil, false, hnyauth.ErrInvalidKey
		}
		return e.info, e.stale, nil
	}

	v, err, _ := c.sf.Do(key, func() (any, error) {
		// Re-check under singleflight in case a concurrent call just populated it.
		if e, st := c.lookup(key); st == stateFresh {
			if e.invalid {
				return nil, hnyauth.ErrInvalidKey
			}
			return resolved{info: e.info, stale: e.stale}, nil
		}
		info, lerr := loader()
		if lerr == nil {
			now := c.now()
			c.lru.Add(key, entry{info: info, refreshAt: now.Add(c.ttl), validatedAt: now})
			return resolved{info: info}, nil
		}
		if errors.Is(lerr, hnyauth.ErrInvalidKey) {
			now := c.now()
			c.lru.Add(key, entry{invalid: true, refreshAt: now.Add(c.negTTL), validatedAt: now})
			return nil, lerr
		}
		// Transient backend failure: serve the stale entry if one is still in
		// its window, pushing refreshAt out so every request during the outage
		// doesn't pay a failed upstream call.
		if e, st := c.lookup(key); st == stateStale {
			c.lru.Add(key, entry{
				info:        e.info,
				stale:       true,
				refreshAt:   c.now().Add(c.negTTL),
				validatedAt: e.validatedAt,
			})
			return resolved{info: e.info, stale: true}, nil
		}
		return nil, lerr
	})
	if err != nil {
		return nil, false, err
	}
	r := v.(resolved)
	return r.info, r.stale, nil
}
