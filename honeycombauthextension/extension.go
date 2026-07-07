// Copyright Honeycomb
// SPDX-License-Identifier: Apache-2.0

package honeycombauthextension // import "github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension"

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensionauth"
	"go.uber.org/zap"

	"github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension/internal/authcache"
	"github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension/internal/hnyauth"
)

var (
	_ extension.Extension  = (*honeycombAuth)(nil)
	_ extensionauth.Server = (*honeycombAuth)(nil)
)

type honeycombAuth struct {
	cfg    *Config
	logger *zap.Logger

	client *hnyauth.Client
	cache  *authcache.Cache
}

func newExtension(cfg *Config, logger *zap.Logger) *honeycombAuth {
	return &honeycombAuth{cfg: cfg, logger: logger}
}

func (h *honeycombAuth) Start(context.Context, component.Host) error {
	c, err := hnyauth.New(h.cfg.Endpoint, h.cfg.Timeout)
	if err != nil {
		return err
	}
	h.client = c
	cache, err := authcache.New(h.cfg.Cache.MaxKeys, h.cfg.Cache.TTL, h.cfg.Cache.NegativeTTL)
	if err != nil {
		return err
	}
	h.cache = cache
	return nil
}

func (h *honeycombAuth) Shutdown(context.Context) error { return nil }

// Authenticate validates the ingest key on the incoming request. It runs on the
// receive hot path, so results are cached (see internal/authcache).
func (h *honeycombAuth) Authenticate(ctx context.Context, headers map[string][]string) (context.Context, error) {
	apiKey := firstHeaderValue(headers, h.cfg.APIKeyHeaders)
	if apiKey == "" {
		return ctx, fmt.Errorf("missing or empty api key header (one of %v)", h.cfg.APIKeyHeaders)
	}

	sum := sha256.Sum256([]byte(apiKey))
	cacheKey := hex.EncodeToString(sum[:])

	info, err := h.cache.Resolve(cacheKey, func() (*hnyauth.AuthInfo, error) {
		return h.client.Lookup(ctx, apiKey)
	})
	if err != nil {
		if errors.Is(err, hnyauth.ErrInvalidKey) {
			return ctx, fmt.Errorf("invalid honeycomb api key: %w", err)
		}
		// Transient failure reaching /1/auth.
		if h.cfg.FailClosed {
			return ctx, fmt.Errorf("honeycomb auth backend unavailable (fail-closed): %w", err)
		}
		h.logger.Warn("honeycomb auth backend unavailable; allowing request (fail-open)", zap.Error(err))
		return ctx, nil
	}

	if h.cfg.RequireIngestScope && !info.APIKeyAccess.Events {
		return ctx, errors.New("honeycomb api key lacks ingest (events) access")
	}

	if h.cfg.Enrich {
		ctx = enrich(ctx, info)
	}
	return ctx, nil
}

// firstHeaderValue returns the first non-empty value across the given header
// names, in order. For each name it tolerates canonical (HTTP) and lower-case
// (gRPC metadata) key forms, which are the only casings those transports
// produce.
func firstHeaderValue(headers map[string][]string, names []string) string {
	for _, name := range names {
		v, ok := headers[http.CanonicalHeaderKey(name)]
		if !ok {
			v, ok = headers[strings.ToLower(name)]
		}
		if ok && len(v) > 0 && v[0] != "" {
			return v[0]
		}
	}
	return ""
}

// authData exposes the resolved team/environment via client.Info.Auth so
// downstream processors can route or stamp on it.
type authData struct {
	env, envSlug, team, teamSlug string
}

func (a *authData) GetAttribute(name string) any {
	switch name {
	case "honeycomb.environment":
		return a.env
	case "honeycomb.environment.slug":
		return a.envSlug
	case "honeycomb.team":
		return a.team
	case "honeycomb.team.slug":
		return a.teamSlug
	default:
		return nil
	}
}

func (a *authData) GetAttributeNames() []string {
	return []string{
		"honeycomb.environment",
		"honeycomb.environment.slug",
		"honeycomb.team",
		"honeycomb.team.slug",
	}
}

func enrich(ctx context.Context, info *hnyauth.AuthInfo) context.Context {
	cl := client.FromContext(ctx)
	cl.Auth = &authData{
		env:      info.Environment.Name,
		envSlug:  info.Environment.Slug,
		team:     info.Team.Name,
		teamSlug: info.Team.Slug,
	}
	return client.NewContext(ctx, cl)
}
