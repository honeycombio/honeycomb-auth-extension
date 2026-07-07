// Copyright Honeycomb
// SPDX-License-Identifier: Apache-2.0

package honeycombauthextension

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	assert.Equal(t, "https://api.honeycomb.io", cfg.Endpoint)
	assert.Equal(t, []string{"x-honeycomb-team", "x-hny-team"}, cfg.APIKeyHeaders)
	assert.Equal(t, 3*time.Second, cfg.Timeout)
	assert.True(t, cfg.FailClosed)
	assert.True(t, cfg.RequireIngestScope)
	assert.True(t, cfg.Enrich)
	assert.Equal(t, 5*time.Minute, cfg.Cache.TTL)
	assert.Equal(t, 30*time.Second, cfg.Cache.NegativeTTL)
	assert.Equal(t, 10000, cfg.Cache.MaxKeys)
	require.NoError(t, cfg.Validate())
}

func TestConfigValidate(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Config)
		wantErr string
	}{
		"no endpoint":      {func(c *Config) { c.Endpoint = "" }, "endpoint"},
		"no headers":       {func(c *Config) { c.APIKeyHeaders = nil }, "api_key_headers"},
		"empty header":     {func(c *Config) { c.APIKeyHeaders = []string{""} }, "api_key_headers"},
		"bad timeout":      {func(c *Config) { c.Timeout = 0 }, "timeout"},
		"bad ttl":          {func(c *Config) { c.Cache.TTL = 0 }, "cache.ttl"},
		"bad negative ttl": {func(c *Config) { c.Cache.NegativeTTL = 0 }, "cache.negative_ttl"},
		"bad max keys":     {func(c *Config) { c.Cache.MaxKeys = 0 }, "cache.max_keys"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := createDefaultConfig().(*Config)
			tc.mutate(cfg)
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
