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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap"

	"github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension/internal/hnyauth"
	"github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension/internal/metadata"
)

const authenticationsMetric = "otelcol_honeycomb_auth.authentications"

// mockAuthServer emulates /1/auth. It counts requests so tests can assert caching.
func mockAuthServer(count *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(count, 1)
		switch r.Header.Get("x-honeycomb-team") {
		case "goodkey":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"api_key_access":{"events":true},"environment":{"name":"prod","slug":"prod"},"team":{"name":"acme","slug":"acme"}}`))
		case "otherteamkey":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"api_key_access":{"events":true},"environment":{"name":"prod","slug":"prod"},"team":{"name":"Other Team","slug":"other-team"}}`))
		case "otherenvkey":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"api_key_access":{"events":true},"environment":{"name":"Staging","slug":"staging"},"team":{"name":"acme","slug":"acme"}}`))
		case "classickey":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"api_key_access":{"events":true},"environment":{"name":"","slug":""},"team":{"name":"acme","slug":"acme"}}`))
		case "noscope":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"api_key_access":{"events":false},"environment":{"name":"prod"},"team":{"name":"acme"}}`))
		case "ingesttypekey":
			// Real ingest key: type=ingest, but api_key_access omits `events`
			// (only createDatasets). Must be accepted under require_ingest_scope.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"type":"ingest","api_key_access":{"createDatasets":true},"environment":{"name":"POC","slug":"poc"},"team":{"name":"raas-eu","slug":"raas-eu"}}`))
		case "badkey":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
}

func newTestExt(t *testing.T, endpoint string, mutate func(*Config)) (*honeycombAuth, *componenttest.Telemetry) {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = endpoint
	cfg.Cache.TTL = time.Minute
	cfg.Cache.NegativeTTL = time.Minute
	if mutate != nil {
		mutate(cfg)
	}
	tt := componenttest.NewTelemetry()
	tb, err := metadata.NewTelemetryBuilder(tt.NewTelemetrySettings())
	require.NoError(t, err)
	h := newExtension(cfg, tb, zap.NewNop())
	require.NoError(t, h.Start(context.Background(), componenttest.NewNopHost()))
	t.Cleanup(func() {
		_ = h.Shutdown(context.Background())
		_ = tt.Shutdown(context.Background())
	})
	return h, tt
}

func headers(key string) map[string][]string {
	return map[string][]string{"x-honeycomb-team": {key}}
}

// outcomeCount returns the authentications counter value for the given outcome.
func outcomeCount(t *testing.T, tt *componenttest.Telemetry, outcome string) int64 {
	t.Helper()
	m, err := tt.GetMetric(authenticationsMetric)
	require.NoError(t, err)
	sum, ok := m.Data.(metricdata.Sum[int64])
	require.True(t, ok, "expected int64 sum data")
	for _, dp := range sum.DataPoints {
		if v, ok := dp.Attributes.Value(attribute.Key("outcome")); ok && v.AsString() == outcome {
			return dp.Value
		}
	}
	return 0
}

// outcomeTeamCount returns the counter value for the datapoint carrying both
// the given outcome and team attributes.
func outcomeTeamCount(t *testing.T, tt *componenttest.Telemetry, outcome, team string) int64 {
	t.Helper()
	m, err := tt.GetMetric(authenticationsMetric)
	require.NoError(t, err)
	sum, ok := m.Data.(metricdata.Sum[int64])
	require.True(t, ok, "expected int64 sum data")
	for _, dp := range sum.DataPoints {
		o, _ := dp.Attributes.Value(attribute.Key("outcome"))
		tm, hasTeam := dp.Attributes.Value(attribute.Key("team"))
		if o.AsString() == outcome && hasTeam && tm.AsString() == team {
			return dp.Value
		}
	}
	return 0
}

// assertNoTeamAttr asserts no datapoint for the given outcome carries a team attribute.
func assertNoTeamAttr(t *testing.T, tt *componenttest.Telemetry, outcome string) {
	t.Helper()
	m, err := tt.GetMetric(authenticationsMetric)
	require.NoError(t, err)
	sum, ok := m.Data.(metricdata.Sum[int64])
	require.True(t, ok, "expected int64 sum data")
	for _, dp := range sum.DataPoints {
		if o, _ := dp.Attributes.Value(attribute.Key("outcome")); o.AsString() == outcome {
			_, hasTeam := dp.Attributes.Value(attribute.Key("team"))
			assert.False(t, hasTeam, "outcome %s must not carry a team attribute", outcome)
		}
	}
}

func TestAuthenticate_ValidKeyEnriches(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, tt := newTestExt(t, srv.URL, nil)

	ctx, err := h.Authenticate(context.Background(), headers("goodkey"))
	require.NoError(t, err)

	cl := client.FromContext(ctx)
	require.NotNil(t, cl.Auth)
	assert.Equal(t, "prod", cl.Auth.GetAttribute("honeycomb.environment"))
	assert.Equal(t, "acme", cl.Auth.GetAttribute("honeycomb.team"))
	assert.Equal(t, int64(1), outcomeCount(t, tt, "valid"))
}

func TestAuthenticate_ShortHeaderAlias(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, _ := newTestExt(t, srv.URL, nil)

	// Key sent on x-hny-team (the short alias) instead of x-honeycomb-team.
	ctx, err := h.Authenticate(context.Background(), map[string][]string{"x-hny-team": {"goodkey"}})
	require.NoError(t, err)
	assert.Equal(t, "prod", client.FromContext(ctx).Auth.GetAttribute("honeycomb.environment"))
}

func TestAuthenticate_CanonicalHeaderCase(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, _ := newTestExt(t, srv.URL, nil)

	// HTTP receivers hand over canonicalized header keys.
	_, err := h.Authenticate(context.Background(), map[string][]string{"X-Honeycomb-Team": {"goodkey"}})
	require.NoError(t, err)
}

func TestAuthenticate_MultiValueHeaderSkipsEmpty(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, _ := newTestExt(t, srv.URL, nil)

	// A leading empty value must not mask a real one.
	_, err := h.Authenticate(context.Background(), map[string][]string{"x-honeycomb-team": {"", "goodkey"}})
	require.NoError(t, err)
}

func TestAuthenticate_MissingHeader(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, tt := newTestExt(t, srv.URL, nil)

	_, err := h.Authenticate(context.Background(), map[string][]string{})
	require.Error(t, err)
	assert.Zero(t, atomic.LoadInt32(&n), "no /1/auth call for a missing header")
	assert.Equal(t, int64(1), outcomeCount(t, tt, "missing_header"))
}

func TestAuthenticate_InvalidKeyRejectedAndNegativelyCached(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, tt := newTestExt(t, srv.URL, nil)

	_, err := h.Authenticate(context.Background(), headers("badkey"))
	require.Error(t, err)
	_, err = h.Authenticate(context.Background(), headers("badkey"))
	require.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&n), "invalid key result should be cached")
	assert.Equal(t, int64(2), outcomeCount(t, tt, "invalid_key"))
}

func TestAuthenticate_ValidKeyCached(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, _ := newTestExt(t, srv.URL, nil)

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
	h, _ := newTestExt(t, srv.URL, nil)

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
	h, _ := newTestExt(t, srv.URL, nil)

	// The outbound lookup is detached from the request context: a cancelled
	// caller must not poison the singleflight result for concurrent requests
	// (and, as here, the lookup itself must still complete).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := h.Authenticate(ctx, headers("goodkey"))
	require.NoError(t, err)
}

func TestAuthenticate_RequireIngestScope(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, tt := newTestExt(t, srv.URL, nil) // require_ingest_scope defaults true

	_, err := h.Authenticate(context.Background(), headers("noscope"))
	require.Error(t, err)
	assert.Equal(t, int64(1), outcomeCount(t, tt, "no_ingest_scope"))
}

func TestAuthenticate_RequireIngestScope_AcceptsIngestType(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, tt := newTestExt(t, srv.URL, nil) // require_ingest_scope defaults true

	// An ingest-type key whose api_key_access omits `events` must still be
	// accepted: type=="ingest" is the authoritative ingest signal.
	_, err := h.Authenticate(context.Background(), headers("ingesttypekey"))
	require.NoError(t, err)
	assert.Equal(t, int64(1), outcomeCount(t, tt, "valid"))
}

func TestAuthenticate_TeamAllowed(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	// Mixed case in config: matching is case-insensitive on the slug.
	h, tt := newTestExt(t, srv.URL, func(c *Config) { c.AllowedTeams = []string{"AcMe", "other-team"} })

	ctx, err := h.Authenticate(context.Background(), headers("goodkey"))
	require.NoError(t, err)
	assert.Equal(t, "acme", client.FromContext(ctx).Auth.GetAttribute("honeycomb.team"))
	assert.Equal(t, int64(1), outcomeCount(t, tt, "valid"))
}

func TestAuthenticate_TeamNotAllowed(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, tt := newTestExt(t, srv.URL, func(c *Config) { c.AllowedTeams = []string{"acme"} })

	ctx, err := h.Authenticate(context.Background(), headers("otherteamkey"))
	require.Error(t, err)
	// The error must not reveal the allow-list or that the key itself is valid.
	assert.NotContains(t, err.Error(), "acme")
	assert.Nil(t, client.FromContext(ctx).Auth, "no enrichment for a rejected request")
	assert.Equal(t, int64(1), outcomeCount(t, tt, "team_not_allowed"))

	// The underlying key stays positively cached: a second rejection makes no
	// further /1/auth call.
	_, err = h.Authenticate(context.Background(), headers("otherteamkey"))
	require.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&n))
}

func TestAuthenticate_EnvironmentAllowed(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	// Mixed case in config: matching is case-insensitive on the slug.
	h, tt := newTestExt(t, srv.URL, func(c *Config) { c.AllowedEnvironments = []string{"PROD"} })

	ctx, err := h.Authenticate(context.Background(), headers("goodkey")) // env slug prod
	require.NoError(t, err)
	assert.Equal(t, "prod", client.FromContext(ctx).Auth.GetAttribute("honeycomb.environment.slug"))
	assert.Equal(t, int64(1), outcomeCount(t, tt, "valid"))
}

func TestAuthenticate_EnvironmentNotAllowed(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, tt := newTestExt(t, srv.URL, func(c *Config) { c.AllowedEnvironments = []string{"prod"} })

	ctx, err := h.Authenticate(context.Background(), headers("otherenvkey")) // env slug staging
	require.Error(t, err)
	// The error must not reveal the allow-list.
	assert.NotContains(t, err.Error(), "prod")
	assert.Nil(t, client.FromContext(ctx).Auth, "no enrichment for a rejected request")
	assert.Equal(t, int64(1), outcomeCount(t, tt, "environment_not_allowed"))

	// The key stays positively cached: rejection makes no further /1/auth call.
	_, err = h.Authenticate(context.Background(), headers("otherenvkey"))
	require.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&n))
}

func TestAuthenticate_ClassicAllowedByDefault(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	// Classic keys have no environment, so the env list must not apply to them.
	h, tt := newTestExt(t, srv.URL, func(c *Config) { c.AllowedEnvironments = []string{"prod"} })

	_, err := h.Authenticate(context.Background(), headers("classickey"))
	require.NoError(t, err)
	assert.Equal(t, int64(1), outcomeCount(t, tt, "valid"))
}

func TestAuthenticate_ClassicDenied(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	// allow_classic is an independent gate: no allowed_environments needed.
	h, tt := newTestExt(t, srv.URL, func(c *Config) { c.AllowClassic = false })

	ctx, err := h.Authenticate(context.Background(), headers("classickey"))
	require.Error(t, err)
	assert.Nil(t, client.FromContext(ctx).Auth)
	assert.Equal(t, int64(1), outcomeCount(t, tt, "classic_not_allowed"))

	// Non-classic keys are unaffected by allow_classic.
	_, err = h.Authenticate(context.Background(), headers("goodkey"))
	require.NoError(t, err)
}

func TestAuthenticate_TransientBackendErrorRejects(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, tt := newTestExt(t, srv.URL, nil)

	// 500 -> transient, and no cached result to serve stale: reject.
	_, err := h.Authenticate(context.Background(), headers("unknown"))
	require.Error(t, err)
	assert.Equal(t, int64(1), outcomeCount(t, tt, "backend_error"))
}

func TestAuthenticate_ServesStaleDuringBackendOutage(t *testing.T) {
	var n int32
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&n, 1)
		if down.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"api_key_access":{"events":true},"environment":{"name":"prod","slug":"prod"},"team":{"name":"acme","slug":"acme"}}`))
	}))
	defer srv.Close()
	h, tt := newTestExt(t, srv.URL, func(c *Config) {
		c.AllowedTeams = []string{"acme"}
		c.Cache.TTL = 50 * time.Millisecond
		c.Cache.StaleTTL = time.Minute
	})

	_, err := h.Authenticate(context.Background(), headers("goodkey"))
	require.NoError(t, err)

	// Backend goes down and the cached result expires: the stale result is
	// served, enrichment and the team check still apply.
	down.Store(true)
	time.Sleep(60 * time.Millisecond)
	ctx, err := h.Authenticate(context.Background(), headers("goodkey"))
	require.NoError(t, err)
	assert.Equal(t, "acme", client.FromContext(ctx).Auth.GetAttribute("honeycomb.team"))
	assert.Equal(t, int64(1), outcomeCount(t, tt, "valid_stale"))
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

	h, _ := newTestExt(t, redirector.URL, nil)

	// A redirecting endpoint is treated as a backend error, and the key is
	// never forwarded to the redirect target.
	_, err := h.Authenticate(context.Background(), headers("goodkey"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "302")
	assert.Zero(t, atomic.LoadInt32(&leaked), "api key must not follow redirects")
}

func TestAuthenticate_TeamAttribute(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	// include_team_attribute defaults to true.
	h, tt := newTestExt(t, srv.URL, func(c *Config) {
		c.AllowedTeams = []string{"acme"}
	})

	_, err := h.Authenticate(context.Background(), headers("goodkey"))
	require.NoError(t, err)
	assert.Equal(t, int64(1), outcomeTeamCount(t, tt, "valid", "acme"))

	// Rejections after the key resolved carry the offending team.
	_, err = h.Authenticate(context.Background(), headers("otherteamkey"))
	require.Error(t, err)
	assert.Equal(t, int64(1), outcomeTeamCount(t, tt, "team_not_allowed", "other-team"))

	// Outcomes where the key never resolved have no team to attach.
	_, err = h.Authenticate(context.Background(), headers("badkey"))
	require.Error(t, err)
	assert.Equal(t, int64(1), outcomeCount(t, tt, "invalid_key"))
	assertNoTeamAttr(t, tt, "invalid_key")
}

func TestAuthenticate_TeamAttributeDisabled(t *testing.T) {
	var n int32
	srv := mockAuthServer(&n)
	defer srv.Close()
	h, tt := newTestExt(t, srv.URL, func(c *Config) {
		c.IncludeTeamAttribute = false
	})

	_, err := h.Authenticate(context.Background(), headers("goodkey"))
	require.NoError(t, err)
	assert.Equal(t, int64(1), outcomeCount(t, tt, "valid"))
	assertNoTeamAttr(t, tt, "valid")
}

// BenchmarkRecordOutcome guards the hot-path cost of the team attribute: after
// the first request per (outcome, team), recording must not build a new
// attribute set, so the on/off allocation counts must match. The single
// remaining allocation is the variadic AddOption slice inherent to the otel
// Add API.
func BenchmarkRecordOutcome(b *testing.B) {
	for _, includeTeam := range []bool{false, true} {
		name := "team_attribute_off"
		if includeTeam {
			name = "team_attribute_on"
		}
		b.Run(name, func(b *testing.B) {
			cfg := createDefaultConfig().(*Config)
			cfg.IncludeTeamAttribute = includeTeam
			tb, err := metadata.NewTelemetryBuilder(componenttest.NewNopTelemetrySettings())
			require.NoError(b, err)
			h := newExtension(cfg, tb, zap.NewNop())
			require.NoError(b, h.Start(context.Background(), componenttest.NewNopHost()))
			defer func() { _ = h.Shutdown(context.Background()) }()

			info := &hnyauth.AuthInfo{}
			info.Team.Name = "acme"
			info.Team.Slug = "acme"

			ctx := context.Background()
			h.recordOutcome(ctx, outcomeValid, info) // warm the cache
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				h.recordOutcome(ctx, outcomeValid, info)
			}
		})
	}
}
