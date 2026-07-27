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
	// short so a rotated/fixed key recovers quickly. Default 30s.
	NegativeTTL time.Duration `mapstructure:"negative_ttl"`
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
	// Timeout bounds each /1/auth call. Default 3s.
	Timeout time.Duration `mapstructure:"timeout"`
	// FailClosed rejects requests when /1/auth cannot be reached (default true).
	// Set false to fail open (allow through; Honeycomb re-validates downstream).
	FailClosed bool `mapstructure:"fail_closed"`
	// RequireIngestScope rejects keys whose api_key_access.events is false (default true).
	RequireIngestScope bool `mapstructure:"require_ingest_scope"`
	// Enrich injects the resolved team/environment into client.Info.Auth for
	// downstream processors (default true).
	Enrich bool `mapstructure:"enrich"`
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
	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if c.Cache.TTL <= 0 {
		return errors.New("cache.ttl must be positive")
	}
	if c.Cache.NegativeTTL <= 0 {
		return errors.New("cache.negative_ttl must be positive")
	}
	if c.Cache.MaxKeys <= 0 {
		return errors.New("cache.max_keys must be positive")
	}
	return nil
}
