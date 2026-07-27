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

func newCache(t *testing.T, maxKeys int, ttl, negTTL, staleTTL time.Duration) *Cache {
	t.Helper()
	c, err := New(maxKeys, ttl, negTTL, staleTTL)
	require.NoError(t, err)
	return c
}

func TestResolve_CachesPositive(t *testing.T) {
	c := newCache(t, 10, time.Minute, time.Minute, 0)
	calls := 0
	load := func() (*hnyauth.AuthInfo, error) { calls++; return &hnyauth.AuthInfo{}, nil }
	for i := 0; i < 3; i++ {
		_, stale, err := c.Resolve("k", load)
		require.NoError(t, err)
		assert.False(t, stale)
	}
	assert.Equal(t, 1, calls)
}

func TestResolve_CachesNegative(t *testing.T) {
	c := newCache(t, 10, time.Minute, time.Minute, 0)
	calls := 0
	load := func() (*hnyauth.AuthInfo, error) { calls++; return nil, hnyauth.ErrInvalidKey }
	for i := 0; i < 3; i++ {
		_, _, err := c.Resolve("k", load)
		require.ErrorIs(t, err, hnyauth.ErrInvalidKey)
	}
	assert.Equal(t, 1, calls)
}

func TestResolve_TransientNotCached(t *testing.T) {
	c := newCache(t, 10, time.Minute, time.Minute, 0)
	calls := 0
	boom := errors.New("boom")
	load := func() (*hnyauth.AuthInfo, error) { calls++; return nil, boom }
	_, _, err := c.Resolve("k", load)
	require.ErrorIs(t, err, boom)
	_, _, err = c.Resolve("k", load)
	require.ErrorIs(t, err, boom)
	assert.Equal(t, 2, calls, "transient errors must not be cached")
}

func TestResolve_Expiry(t *testing.T) {
	c := newCache(t, 10, 10*time.Second, 10*time.Second, 0)
	base := time.Now()
	cur := base
	c.now = func() time.Time { return cur }

	calls := 0
	load := func() (*hnyauth.AuthInfo, error) { calls++; return &hnyauth.AuthInfo{}, nil }

	_, _, _ = c.Resolve("k", load)
	cur = base.Add(11 * time.Second) // past TTL
	_, _, _ = c.Resolve("k", load)
	assert.Equal(t, 2, calls)
}

func TestResolve_ServesStaleOnTransientError(t *testing.T) {
	c := newCache(t, 10, 10*time.Second, 5*time.Second, time.Hour)
	base := time.Now()
	cur := base
	c.now = func() time.Time { return cur }

	info := &hnyauth.AuthInfo{}
	info.Team.Slug = "acme"
	loadOK := func() (*hnyauth.AuthInfo, error) { return info, nil }
	boom := errors.New("backend down")
	calls := 0
	loadFail := func() (*hnyauth.AuthInfo, error) { calls++; return nil, boom }

	_, stale, err := c.Resolve("k", loadOK)
	require.NoError(t, err)
	assert.False(t, stale)

	// Past the positive TTL, refresh fails transiently: the stale result is
	// served and still carries the AuthInfo (team check downstream needs it).
	cur = base.Add(11 * time.Second)
	got, stale, err := c.Resolve("k", loadFail)
	require.NoError(t, err)
	assert.True(t, stale)
	assert.Equal(t, "acme", got.Team.Slug)
	assert.Equal(t, 1, calls)

	// Within the retry interval (negTTL) the stale entry is served without
	// another upstream attempt, and stays flagged stale.
	cur = cur.Add(2 * time.Second)
	_, stale, err = c.Resolve("k", loadFail)
	require.NoError(t, err)
	assert.True(t, stale)
	assert.Equal(t, 1, calls, "no retry within the retry interval")

	// After the retry interval a recovered backend refreshes the entry.
	cur = cur.Add(6 * time.Second)
	_, stale, err = c.Resolve("k", loadOK)
	require.NoError(t, err)
	assert.False(t, stale, "successful refresh clears staleness")
}

func TestResolve_StaleWindowBounded(t *testing.T) {
	c := newCache(t, 10, 10*time.Second, 5*time.Second, 30*time.Second)
	base := time.Now()
	cur := base
	c.now = func() time.Time { return cur }

	boom := errors.New("backend down")
	loadOK := func() (*hnyauth.AuthInfo, error) { return &hnyauth.AuthInfo{}, nil }
	loadFail := func() (*hnyauth.AuthInfo, error) { return nil, boom }

	_, _, err := c.Resolve("k", loadOK)
	require.NoError(t, err)

	// Past validatedAt + staleTTL the entry is gone: the transient error
	// surfaces even though a (too-old) result once existed.
	cur = base.Add(31 * time.Second)
	_, _, err = c.Resolve("k", loadFail)
	require.ErrorIs(t, err, boom)
}

func TestResolve_StaleDisabled(t *testing.T) {
	c := newCache(t, 10, 10*time.Second, 5*time.Second, 0)
	base := time.Now()
	cur := base
	c.now = func() time.Time { return cur }

	boom := errors.New("backend down")
	loadOK := func() (*hnyauth.AuthInfo, error) { return &hnyauth.AuthInfo{}, nil }
	loadFail := func() (*hnyauth.AuthInfo, error) { return nil, boom }

	_, _, err := c.Resolve("k", loadOK)
	require.NoError(t, err)

	cur = base.Add(11 * time.Second)
	_, _, err = c.Resolve("k", loadFail)
	require.ErrorIs(t, err, boom, "stale_ttl 0 disables fallback")
}

func TestResolve_NegativeNeverServedStale(t *testing.T) {
	c := newCache(t, 10, 10*time.Second, 5*time.Second, time.Hour)
	base := time.Now()
	cur := base
	c.now = func() time.Time { return cur }

	boom := errors.New("backend down")
	loadInvalid := func() (*hnyauth.AuthInfo, error) { return nil, hnyauth.ErrInvalidKey }
	loadFail := func() (*hnyauth.AuthInfo, error) { return nil, boom }

	_, _, err := c.Resolve("k", loadInvalid)
	require.ErrorIs(t, err, hnyauth.ErrInvalidKey)

	// An expired negative entry is not a stale fallback.
	cur = base.Add(6 * time.Second)
	_, _, err = c.Resolve("k", loadFail)
	require.ErrorIs(t, err, boom)
}

func TestEviction_BoundsSize(t *testing.T) {
	c := newCache(t, 2, time.Minute, time.Minute, 0)
	load := func() (*hnyauth.AuthInfo, error) { return &hnyauth.AuthInfo{}, nil }
	_, _, _ = c.Resolve("a", load)
	_, _, _ = c.Resolve("b", load)
	_, _, _ = c.Resolve("c", load)
	assert.LessOrEqual(t, c.lru.Len(), 2)
}
