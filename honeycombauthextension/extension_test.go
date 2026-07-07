// Copyright Honeycomb
// SPDX-License-Identifier: Apache-2.0

package honeycombauthextension

import (
	"context"
	"net/http"
	"net/http/httptest"
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
