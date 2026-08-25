// Copyright Honeycomb
// SPDX-License-Identifier: Apache-2.0

package honeycombauthextension // import "github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension"

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
)

// CacheConfig controls caching of /1/auth validation results.
type CacheConfig struct {
	// TTL is how long a successful validation is cached. This is also the
	// upper bound on how long a revoked key keeps working. Default 5m.
	TTL time.Duration `mapstructure:"ttl"`
	// NegativeTTL is how long an invalid-key (401) result is cached. Keep it
	// short so a rotated/fixed key recovers quickly. It is also the retry
	// interval for revalidating a result served stale. Default 30s.
	NegativeTTL time.Duration `mapstructure:"negative_ttl"`
	// StaleTTL is how long past a successful validation a cached result may
	// still be served if /1/auth is unreachable when it is due for refresh,
	// so an auth-backend outage does not drop established traffic. Requests
	// with no (stale) cached result are rejected during an outage. 0 disables
	// stale serving. Default 1h.
	StaleTTL time.Duration `mapstructure:"stale_ttl"`
	// MaxKeys bounds the number of cached keys (LRU). Default 10000.
	MaxKeys int `mapstructure:"max_keys"`
}

// Config is the configuration for the honeycomb_auth extension.
type Config struct {
	// Endpoint is the Honeycomb API base URL that /1/auth is called against.
	// US: https://api.honeycomb.io (default). EU: https://api.eu1.honeycomb.io.
	Endpoint string `mapstructure:"endpoint"`
	// APIKeyHeaders are the request headers to read the ingest key from, in
	// order; the first non-empty one wins. Default [x-honeycomb-team, x-hny-team].
	APIKeyHeaders []string `mapstructure:"api_key_headers"`
	// AllowedTeams restricts which teams' keys are accepted: a key whose
	// /1/auth team slug is not in this list is rejected as if it were invalid.
	// Empty (default) accepts keys from any team.
	AllowedTeams []string `mapstructure:"allowed_teams"`
	// AllowedEnvironments restricts which environments' keys are accepted,
	// matched against the /1/auth environment slug. Empty (default) accepts
	// any environment. Classic keys carry no environment and are not subject
	// to this list; gate them with AllowClassic.
	AllowedEnvironments []string `mapstructure:"allowed_environments"`
	// AllowClassic accepts Honeycomb Classic keys, which have no environment
	// (default true). Set false to reject them; this applies whether or not
	// allowed_environments is set.
	AllowClassic bool `mapstructure:"allow_classic"`
	// Timeout bounds each /1/auth call. Default 3s.
	Timeout time.Duration `mapstructure:"timeout"`
	// RequireIngestScope rejects keys that lack ingest access (default true).
	// A key satisfies it if type == "ingest" OR api_key_access.events is true —
	// ingest keys don't always list `events`, so type is the primary signal.
	RequireIngestScope bool `mapstructure:"require_ingest_scope"`
	// Enrich injects the resolved team/environment into client.Info.Auth for
	// downstream processors (default true).
	Enrich bool `mapstructure:"enrich"`
	// IncludeTeamAttribute adds the resolved team slug as a `team` attribute on
	// the authentications metric (default true). Only outcomes where the key
	// resolved via /1/auth carry it (missing_header, invalid_key, and
	// backend_error have no team). Metric cardinality grows with the number of
	// distinct teams whose valid keys reach this collector, including rejected
	// ones (team_not_allowed carries the foreign team's slug); set false if
	// that is a concern, e.g. a public endpoint in a cardinality-sensitive
	// fleet.
	IncludeTeamAttribute bool `mapstructure:"include_team_attribute"`
	// Cache configures validation-result caching.
	Cache CacheConfig `mapstructure:"cache"`

	// prevent unkeyed literal initialization
	_ struct{}
}

var _ component.Config = (*Config)(nil)

// Validate checks the extension configuration.
func (c *Config) Validate() error {
	if c.Endpoint == "" {
		return errors.New("endpoint must be set")
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint %q: %w", c.Endpoint, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("endpoint must be an http(s) URL with a host, got %q", c.Endpoint)
	}
	if len(c.APIKeyHeaders) == 0 {
		return errors.New("api_key_headers must list at least one header")
	}
	for _, h := range c.APIKeyHeaders {
		if h == "" {
			return errors.New("api_key_headers must not contain empty entries")
		}
	}
	for _, team := range c.AllowedTeams {
		if strings.TrimSpace(team) == "" {
			return errors.New("allowed_teams must not contain empty entries")
		}
	}
	for _, env := range c.AllowedEnvironments {
		if strings.TrimSpace(env) == "" {
			return errors.New("allowed_environments must not contain empty entries")
		}
	}
	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if c.Cache.TTL <= 0 {
		return errors.New("cache.ttl must be positive")
	}
	if c.Cache.NegativeTTL <= 0 {
		return errors.New("cache.negative_ttl must be positive")
	}
	if c.Cache.StaleTTL < 0 {
		return errors.New("cache.stale_ttl must not be negative")
	}
	if c.Cache.MaxKeys <= 0 {
		return errors.New("cache.max_keys must be positive")
	}
	return nil
}
