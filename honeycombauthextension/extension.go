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
	"time"

	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensionauth"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension/internal/authcache"
	"github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension/internal/hnyauth"
	"github.com/honeycombio/honeycomb-auth-extension/honeycombauthextension/internal/metadata"
)

var (
	_ extension.Extension  = (*honeycombAuth)(nil)
	_ extensionauth.Server = (*honeycombAuth)(nil)
)

// Outcome attribute values for the authentications counter. Attribute sets are
// precomputed because Authenticate is on the receive hot path.
var (
	outcomeValid          = outcomeOpt("valid")
	outcomeValidStale     = outcomeOpt("valid_stale")
	outcomeMissingHeader  = outcomeOpt("missing_header")
	outcomeInvalidKey     = outcomeOpt("invalid_key")
	outcomeTeamNotAllowed = outcomeOpt("team_not_allowed")
	outcomeNoIngestScope  = outcomeOpt("no_ingest_scope")
	outcomeBackendError   = outcomeOpt("backend_error")
)

func outcomeOpt(outcome string) metric.AddOption {
	return metric.WithAttributeSet(attribute.NewSet(attribute.String("outcome", outcome)))
}

type honeycombAuth struct {
	cfg       *Config
	logger    *zap.Logger
	telemetry *metadata.TelemetryBuilder

	// sampledLogger rate-limits warnings emitted per rejected request, so a
	// flood of unauthorized traffic can't drown the collector's logs.
	sampledLogger *zap.Logger

	client       *hnyauth.Client
	cache        *authcache.Cache
	allowedTeams map[string]struct{}
}

func newExtension(cfg *Config, telemetry *metadata.TelemetryBuilder, logger *zap.Logger) *honeycombAuth {
	return &honeycombAuth{
		cfg:       cfg,
		logger:    logger,
		telemetry: telemetry,
		sampledLogger: zap.New(zapcore.NewSamplerWithOptions(
			logger.Core(), 10*time.Second, 5, 0,
		)),
	}
}

func (h *honeycombAuth) Start(context.Context, component.Host) error {
	h.client = hnyauth.New(h.cfg.Endpoint, h.cfg.Timeout)
	cache, err := authcache.New(h.cfg.Cache.MaxKeys, h.cfg.Cache.TTL, h.cfg.Cache.NegativeTTL, h.cfg.Cache.StaleTTL)
	if err != nil {
		return err
	}
	h.cache = cache
	h.allowedTeams = make(map[string]struct{}, len(h.cfg.AllowedTeams))
	for _, team := range h.cfg.AllowedTeams {
		h.allowedTeams[strings.ToLower(team)] = struct{}{}
	}
	return nil
}

func (h *honeycombAuth) Shutdown(context.Context) error {
	if h.client != nil {
		h.client.Close()
	}
	if h.telemetry != nil {
		h.telemetry.Shutdown()
	}
	return nil
}

// Authenticate validates the ingest key on the incoming request. It runs on the
// receive hot path, so results are cached (see internal/authcache).
func (h *honeycombAuth) Authenticate(ctx context.Context, headers map[string][]string) (context.Context, error) {
	apiKey := firstHeaderValue(headers, h.cfg.APIKeyHeaders)
	if apiKey == "" {
		h.telemetry.HoneycombAuthAuthentications.Add(ctx, 1, outcomeMissingHeader)
		return ctx, fmt.Errorf("missing or empty api key header (one of %v)", h.cfg.APIKeyHeaders)
	}

	sum := sha256.Sum256([]byte(apiKey))
	cacheKey := string(sum[:])

	info, stale, err := h.cache.Resolve(cacheKey, func() (*hnyauth.AuthInfo, error) {
		// Detached from the request context: the loader's result is shared by
		// every request collapsed onto this key by the singleflight, so one
		// cancelled caller must not fail the rest. http.Client.Timeout still
		// bounds the call.
		return h.client.Lookup(context.WithoutCancel(ctx), apiKey)
	})
	if err != nil {
		if errors.Is(err, hnyauth.ErrInvalidKey) {
			h.telemetry.HoneycombAuthAuthentications.Add(ctx, 1, outcomeInvalidKey)
			return ctx, fmt.Errorf("invalid honeycomb api key: %w", err)
		}
		// Transient failure reaching /1/auth with no stale result to fall
		// back on: reject. Keys validated within cache.stale_ttl are served
		// stale instead (see internal/authcache), so this only hits senders
		// unknown to this collector during an auth-backend outage.
		h.telemetry.HoneycombAuthAuthentications.Add(ctx, 1, outcomeBackendError)
		return ctx, fmt.Errorf("honeycomb auth backend unavailable: %w", err)
	}

	if h.cfg.RequireIngestScope && !info.APIKeyAccess.Events {
		h.telemetry.HoneycombAuthAuthentications.Add(ctx, 1, outcomeNoIngestScope)
		return ctx, errors.New("honeycomb api key lacks ingest (events) access")
	}

	if len(h.allowedTeams) > 0 {
		if _, ok := h.allowedTeams[strings.ToLower(info.Team.Slug)]; !ok {
			h.sampledLogger.Warn("rejecting valid honeycomb api key: team is not in allowed_teams",
				zap.String("team", info.Team.Name),
				zap.String("team_slug", info.Team.Slug),
				zap.String("key_hash_prefix", hex.EncodeToString(sum[:4])),
			)
			h.telemetry.HoneycombAuthAuthentications.Add(ctx, 1, outcomeTeamNotAllowed)
			// Deliberately indistinguishable from an invalid key to the sender,
			// and no hint of which teams are allowed.
			return ctx, errors.New("honeycomb api key is not authorized for this collector")
		}
	}

	if stale {
		h.sampledLogger.Warn("serving stale auth result; /1/auth unreachable",
			zap.String("team_slug", info.Team.Slug),
			zap.String("key_hash_prefix", hex.EncodeToString(sum[:4])),
		)
		h.telemetry.HoneycombAuthAuthentications.Add(ctx, 1, outcomeValidStale)
	} else {
		h.telemetry.HoneycombAuthAuthentications.Add(ctx, 1, outcomeValid)
	}

	if h.cfg.Enrich {
		ctx = enrich(ctx, info)
	}
	return ctx, nil
}

// firstHeaderValue returns the first non-empty value across the given header
// names, in order. For each name it tolerates canonical (HTTP) and lower-case
// (gRPC metadata) key forms, which are the only casings those transports
// produce, and scans all values for a name so a leading empty value doesn't
// mask a real one.
func firstHeaderValue(headers map[string][]string, names []string) string {
	for _, name := range names {
		for _, form := range [2]string{http.CanonicalHeaderKey(name), strings.ToLower(name)} {
			for _, v := range headers[form] {
				if v != "" {
					return v
				}
			}
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
