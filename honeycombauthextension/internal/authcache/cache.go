// Copyright Honeycomb
// SPDX-License-Identifier: Apache-2.0

// Package authcache caches /1/auth validation results with separate positive
// and negative TTLs. It uses github.com/hashicorp/golang-lru/v2 (the LRU library
// standard across the Collector and contrib) for bounded eviction, and expires
// entries lazily on read (the base LRU has no background goroutine, so there is
// nothing to stop on Shutdown). Concurrent misses for the same key are collapsed
// with a singleflight so a burst of first-time requests makes only one upstream
// call.
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
	expires time.Time
}

// Cache holds positive (valid AuthInfo) and negative (invalid key) results.
type Cache struct {
	lru    *lru.Cache[string, entry]
	ttl    time.Duration
	negTTL time.Duration
	sf     singleflight.Group
	now    func() time.Time // overridable in tests
}

// New builds a cache bounded to maxKeys entries, with ttl for positive results
// and negTTL for negative results.
func New(maxKeys int, ttl, negTTL time.Duration) (*Cache, error) {
	l, err := lru.New[string, entry](maxKeys)
	if err != nil {
		return nil, err
	}
	return &Cache{
		lru:    l,
		ttl:    ttl,
		negTTL: negTTL,
		now:    time.Now,
	}, nil
}

func (c *Cache) lookup(key string) (entry, bool) {
	e, ok := c.lru.Get(key)
	if !ok {
		return entry{}, false
	}
	if c.now().After(e.expires) {
		c.lru.Remove(key)
		return entry{}, false
	}
	return e, true
}

// Resolve returns the cached result for key, or calls loader exactly once (per
// concurrent set of callers) on a miss. A returned hnyauth.ErrInvalidKey is
// cached negatively; any other loader error is NOT cached (so transient
// auth-backend failures don't stick). key should be a digest of the API key
// (raw digest bytes as a string are fine), never the key itself.
func (c *Cache) Resolve(key string, loader func() (*hnyauth.AuthInfo, error)) (*hnyauth.AuthInfo, error) {
	if e, ok := c.lookup(key); ok {
		if e.invalid {
			return nil, hnyauth.ErrInvalidKey
		}
		return e.info, nil
	}

	v, err, _ := c.sf.Do(key, func() (any, error) {
		// Re-check under singleflight in case a concurrent call just populated it.
		if e, ok := c.lookup(key); ok {
			if e.invalid {
				return nil, hnyauth.ErrInvalidKey
			}
			return e.info, nil
		}
		info, lerr := loader()
		if lerr != nil {
			if errors.Is(lerr, hnyauth.ErrInvalidKey) {
				c.lru.Add(key, entry{invalid: true, expires: c.now().Add(c.negTTL)})
			}
			return nil, lerr
		}
		c.lru.Add(key, entry{info: info, expires: c.now().Add(c.ttl)})
		return info, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*hnyauth.AuthInfo), nil
}
