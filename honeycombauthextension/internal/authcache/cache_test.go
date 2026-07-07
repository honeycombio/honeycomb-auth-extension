// Copyright Honeycomb
// SPDX-License-Identifier: Apache-2.0

package authcache

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension/internal/hnyauth"
)

func newCache(t *testing.T, maxKeys int, ttl, negTTL time.Duration) *Cache {
	t.Helper()
	c, err := New(maxKeys, ttl, negTTL)
	require.NoError(t, err)
	return c
}

func TestResolve_CachesPositive(t *testing.T) {
	c := newCache(t, 10, time.Minute, time.Minute)
	calls := 0
	load := func() (*hnyauth.AuthInfo, error) { calls++; return &hnyauth.AuthInfo{}, nil }
	for i := 0; i < 3; i++ {
		_, err := c.Resolve("k", load)
		require.NoError(t, err)
	}
	assert.Equal(t, 1, calls)
}

func TestResolve_CachesNegative(t *testing.T) {
	c := newCache(t, 10, time.Minute, time.Minute)
	calls := 0
	load := func() (*hnyauth.AuthInfo, error) { calls++; return nil, hnyauth.ErrInvalidKey }
	for i := 0; i < 3; i++ {
		_, err := c.Resolve("k", load)
		require.ErrorIs(t, err, hnyauth.ErrInvalidKey)
	}
	assert.Equal(t, 1, calls)
}

func TestResolve_TransientNotCached(t *testing.T) {
	c := newCache(t, 10, time.Minute, time.Minute)
	calls := 0
	boom := errors.New("boom")
	load := func() (*hnyauth.AuthInfo, error) { calls++; return nil, boom }
	_, err := c.Resolve("k", load)
	require.ErrorIs(t, err, boom)
	_, err = c.Resolve("k", load)
	require.ErrorIs(t, err, boom)
	assert.Equal(t, 2, calls, "transient errors must not be cached")
}

func TestResolve_Expiry(t *testing.T) {
	c := newCache(t, 10, 10*time.Second, 10*time.Second)
	base := time.Now()
	cur := base
	c.now = func() time.Time { return cur }

	calls := 0
	load := func() (*hnyauth.AuthInfo, error) { calls++; return &hnyauth.AuthInfo{}, nil }

	_, _ = c.Resolve("k", load)
	cur = base.Add(11 * time.Second) // past TTL
	_, _ = c.Resolve("k", load)
	assert.Equal(t, 2, calls)
}

func TestEviction_BoundsSize(t *testing.T) {
	c := newCache(t, 2, time.Minute, time.Minute)
	load := func() (*hnyauth.AuthInfo, error) { return &hnyauth.AuthInfo{}, nil }
	_, _ = c.Resolve("a", load)
	_, _ = c.Resolve("b", load)
	_, _ = c.Resolve("c", load)
	assert.LessOrEqual(t, c.lru.Len(), 2)
}
