// Copyright Honeycomb
// SPDX-License-Identifier: Apache-2.0

package honeycombauthextension // import "github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension"

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"

	"github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension/internal/metadata"
)

// NewFactory creates a factory for the honeycombauth extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		createDefaultConfig,
		createExtension,
		metadata.ExtensionStability,
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		Endpoint:           "https://api.honeycomb.io",
		APIKeyHeaders:      []string{"x-honeycomb-team", "x-hny-team"},
		Timeout:            3 * time.Second,
		FailClosed:         true,
		RequireIngestScope: true,
		Enrich:             true,
		Cache: CacheConfig{
			TTL:         5 * time.Minute,
			NegativeTTL: 30 * time.Second,
			MaxKeys:     10000,
		},
	}
}

func createExtension(_ context.Context, set extension.Settings, cfg component.Config) (extension.Extension, error) {
	return newExtension(cfg.(*Config), set.Logger), nil
}
