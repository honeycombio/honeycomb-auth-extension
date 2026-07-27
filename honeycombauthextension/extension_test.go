// Copyright Honeycomb
// SPDX-License-Identifier: Apache-2.0

package honeycombauthextension

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.uber.org/zap"
)

// mockAuthServer emulates /1/auth. It counts requests so tests can assert caching.
func mockAuthServer(count *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(count, 1)
		switch r.Header.Get("x-honeycomb-team") {
		case "goodkey":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"api_key_access":{"events":true},"environment":{"name":"prod","slug":"prod"},"team":{"name":"acme","slug":"acme"}}`))
		case "noscope":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"api_key_access":{"events":false},"environment":{"name":"prod"},"team":{"name":"acme"}}`))
		case "badkey":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
}

func newTestExt(t *testing.T, endpoint string, mutate func(*Config)) *honeycombAuth {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = endpoint
	cfg.Cache.TTL = time.Minute
	cfg.Cache.NegativeTTL = time.Minute
	if mutate != nil {
		mutate(cfg)
	}
	h := newExtension(cfg, zap.NewNop())
	require.NoError(t, h.Start(context.Background(), componenttest.NewNopHost()))
	t.Cleanup(func() { _ = h.Shutdown(context.Background()) })
	return h
}

func headers(key string) map[string][]string {
	return map[string][]string{"x-honeycomb-team": {key}}
}

func TestAuthenticate_ValidKeyEnriches(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h := newTestExt(t, srv.URL, nil)

	ctx, err := h.Authenticate(context.Background(), headers("goodkey"))
	require.NoError(t, err)

	cl := client.FromContext(ctx)
	require.NotNil(t, cl.Auth)
	assert.Equal(t, "prod", cl.Auth.GetAttribute("honeycomb.environment"))
	assert.Equal(t, "acme", cl.Auth.GetAttribute("honeycomb.team"))
}

func TestAuthenticate_ShortHeaderAlias(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h := newTestExt(t, srv.URL, nil)

	// Key sent on x-hny-team (the short alias) instead of x-honeycomb-team.
	ctx, err := h.Authenticate(context.Background(), map[string][]string{"x-hny-team": {"goodkey"}})
	require.NoError(t, err)
	assert.Equal(t, "prod", client.FromContext(ctx).Auth.GetAttribute("honeycomb.environment"))
}

func TestAuthenticate_CanonicalHeaderCase(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h := newTestExt(t, srv.URL, nil)

	// HTTP receivers hand over canonicalized header keys.
	_, err := h.Authenticate(context.Background(), map[string][]string{"X-Honeycomb-Team": {"goodkey"}})
	require.NoError(t, err)
}

func TestAuthenticate_MultiValueHeaderSkipsEmpty(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h := newTestExt(t, srv.URL, nil)

	// A leading empty value must not mask a real one.
	_, err := h.Authenticate(context.Background(), map[string][]string{"x-honeycomb-team": {"", "goodkey"}})
	require.NoError(t, err)
}

func TestAuthenticate_MissingHeader(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h := newTestExt(t, srv.URL, nil)

	_, err := h.Authenticate(context.Background(), map[string][]string{})
	require.Error(t, err)
	assert.Zero(t, atomic.LoadInt32(&n), "no /1/auth call for a missing header")
}

func TestAuthenticate_InvalidKeyRejectedAndNegativelyCached(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h := newTestExt(t, srv.URL, nil)

	_, err := h.Authenticate(context.Background(), headers("badkey"))
	require.Error(t, err)
	_, err = h.Authenticate(context.Background(), headers("badkey"))
	require.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&n), "invalid key result should be cached")
}

func TestAuthenticate_ValidKeyCached(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h := newTestExt(t, srv.URL, nil)

	for i := 0; i < 3; i++ {
		_, err := h.Authenticate(context.Background(), headers("goodkey"))
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), atomic.LoadInt32(&n), "valid key result should be cached")
}

func TestAuthenticate_ConcurrentRequestsCollapseToOneLookup(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h := newTestExt(t, srv.URL, nil)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.Authenticate(context.Background(), headers("goodkey"))
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), atomic.LoadInt32(&n), "concurrent first requests should singleflight")
}

func TestAuthenticate_CancelledContextStillValidates(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h := newTestExt(t, srv.URL, nil)

	// The outbound lookup is detached from the request context: a cancelled
	// caller must not poison the singleflight result for concurrent requests
	// (and, as here, the lookup itself must still complete).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := h.Authenticate(ctx, headers("goodkey"))
	require.NoError(t, err)
}

func TestAuthenticate_RedirectNotFollowed(t *testing.T) {
	var leaked int32
	attacker := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-honeycomb-team") != "" {
			atomic.AddInt32(&leaked, 1)
		}
	}))
	defer attacker.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL, http.StatusFound)
	}))
	defer redirector.Close()

	h := newTestExt(t, redirector.URL, nil)

	// A redirecting endpoint is treated as a backend error, and the key is
	// never forwarded to the redirect target.
	_, err := h.Authenticate(context.Background(), headers("goodkey"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "302")
	assert.Zero(t, atomic.LoadInt32(&leaked), "api key must not follow redirects")
}

func TestAuthenticate_RequireIngestScope(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h := newTestExt(t, srv.URL, nil) // require_ingest_scope defaults true

	_, err := h.Authenticate(context.Background(), headers("noscope"))
	require.Error(t, err)
}

func TestAuthenticate_TransientFailClosed(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h := newTestExt(t, srv.URL, nil) // fail_closed defaults true

	_, err := h.Authenticate(context.Background(), headers("unknown")) // 500 -> transient
	require.Error(t, err)
}

func TestAuthenticate_TransientFailOpen(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h := newTestExt(t, srv.URL, func(c *Config) { c.FailClosed = false })

	_, err := h.Authenticate(context.Background(), headers("unknown")) // 500 -> transient, allowed
	require.NoError(t, err)
}
