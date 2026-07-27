# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## What this is

An OpenTelemetry Collector server-authenticator extension (type `honeycomb_auth`) that validates
the incoming `x-honeycomb-team` ingest key against Honeycomb's `/1/auth` endpoint, caches the
result, optionally restricts accepted teams (`allowed_teams`), and optionally injects the resolved
team/environment into `client.Info.Auth`. It is a single Go module under `honeycombauthextension/`
(directory keeps the concatenated name per upstream convention, e.g. `headers_setter` in
`headerssetterextension/`).

Requires Go 1.25+ (`GOTOOLCHAIN=auto` fetches it). Collector deps are pinned to v1.61.0 (stable) /
v0.155.0 (unstable) to match `honeycombio/honeycomb-collector-distro`.

## Common commands

```bash
make test        # go test -race in honeycombauthextension/
make vet         # go vet
make lint        # go vet + golangci-lint (if installed), config .golangci.yml
make generate    # mdatagen from honeycombauthextension/metadata.yaml -> internal/metadata/
make example     # build + run the example distro (example/run.sh)
make e2e         # automated e2e suite (e2e/run.sh): real distro + mock, asserts
                 # status codes, outcome metrics, warn logs; runs in CI
make tidy        # go mod tidy
```

## Layout

- `honeycombauthextension/` — the component module.
  - `factory.go` — `extension.NewFactory` wiring (type `honeycomb_auth`, alpha) + TelemetryBuilder.
  - `config.go` — `Config` + `Validate` (endpoint, api_key_headers, allowed_teams, timeout,
    require_ingest_scope, enrich, cache TTLs incl. stale_ttl).
  - `extension.go` — implements `extensionauth.Server.Authenticate`; header extraction, cache lookup,
    scope check, team allow-list, enrichment, outcome metric
    (`otelcol_honeycomb_auth.authentications`), sampled warn logs.
  - `internal/hnyauth/` — `/1/auth` client + `AuthInfo` (ported from Refinery). Owns its transport;
    never follows redirects (the key would be forwarded to the redirect target).
  - `internal/authcache/` — positive/negative TTL cache over `hashicorp/golang-lru/v2` (base package,
    goroutine-free) with singleflight. Serves stale positive results (within `stale_ttl`) when
    revalidation fails transiently; there is deliberately NO fail-open, so unknown keys are
    rejected during an auth-backend outage.
  - `internal/metadata/`, `internal/metadatatest/` — mdatagen output (do not hand-edit; run
    `make generate`).
- `internal/tools/` — separate module pinning build tools (mdatagen), the contrib pattern; keeps
  tool deps out of the component module's graph. `go run/install pkg@version` cannot be used for
  mdatagen (its go.mod has replace directives).
- `example/` — OCB `builder-config.yaml` + `config.yaml` + `mock_auth.py` + `build.sh`/`run.sh` for
  interactive use. The mock also serves the e2e suite (POST /down and /up toggle an outage).
- `e2e/` — automated end-to-end suite (`run.sh` + `config.yaml`): builds the example distro,
  exercises every auth scenario over real OTLP/HTTP, asserts status codes, the
  `otelcol_honeycomb_auth_authentications` outcome counters, and the sampled warn logs.

## Gotchas

- The root `go.work` breaks the OCB build (it cd's into the generated `example/_build` module). Build
  the example with `GOWORK=off` (already handled in `example/run.sh`).
- `internal/metadata/` is generated. Change `metadata.yaml` and run `make generate`, don't hand-edit.
- `Authenticate` is on the receive hot path: keep it fast, rely on the cache; don't add blocking work.
- The outbound `/1/auth` call always uses `x-honeycomb-team` regardless of which inbound alias
  (`x-honeycomb-team` / `x-hny-team`) the client used.
- The outbound lookup runs under `context.WithoutCancel`: the singleflight result is shared, so one
  cancelled caller must not fail the collapsed peers. Don't reattach request-cancellation there.
- The `allowed_teams` check is per-request over the *cached* AuthInfo (like the scope check), not
  part of the cache key/value; keep the cache config-agnostic.

## Prior art

Refinery's `/1/auth` + environment cache (`route/route.go`) and Elastic's `apikeyauth` extension
(external validation + TTL cache) are the reference implementations.
