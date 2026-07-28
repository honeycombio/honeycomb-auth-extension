# honeycomb-auth-extension changelog

## Unreleased

- `allowed_environments` restricts accepted keys to specific environment slugs (E&S keys)
- `allow_classic` (default true) gates Honeycomb Classic keys, which carry no environment
- New metric outcomes: `environment_not_allowed`, `classic_not_allowed`

## honeycombauthextension/v0.1.0 (2026-07-28)

Initial release of the `honeycomb_auth` server-authenticator extension.

- Validates inbound `x-honeycomb-team` / `x-hny-team` ingest keys against Honeycomb's `/1/auth`
- `allowed_teams` restricts accepted keys to specific team slugs
- Positive/negative result caching with singleflight, plus stale serving during `/1/auth`
  outages (`cache.stale_ttl`); no fail-open path
- Optional enrichment of `client.Info.Auth` with the resolved team/environment
- Self-telemetry counter `otelcol_honeycomb_auth.authentications` with per-outcome attribute
- Hardened outbound client: never follows redirects, dedicated pooled transport, response
  size caps
