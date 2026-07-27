# honeycomb-auth-extension

An OpenTelemetry Collector [server authenticator](https://opentelemetry.io/docs/collector/configuration/#authentication)
extension (`honeycomb_auth`) that validates the incoming `x-honeycomb-team` ingest key against
Honeycomb's `/1/auth` endpoint, caches the result, optionally restricts which teams' keys are
accepted, and (optionally) injects the resolved team/environment into `client.Info.Auth` for
downstream components.

Because it runs inside the Collector, it is infrastructure-agnostic: the auth check travels with the
collector and works the same wherever it runs (any cloud, on-prem, or a customer-hosted collector),
with no dependency on a particular load balancer, API gateway, or managed edge service.

## Why

Honeycomb ingest keys are opaque, so validating one means calling `/1/auth` (a 401 means the key is
invalid/revoked; the response body carries the team, environment, and `api_key_access` scopes). No
stock Collector auth extension does an external-API lookup (`bearertokenauth` only compares static
tokens), and load-balancer/edge auth can't call an arbitrary API to validate an opaque key. This
extension fills that gap, and doubles as an environment resolver (same call).

For a collector hosted for a specific customer, validating that a key is *some* team's valid key is
not enough: `allowed_teams` pins the collector to the intended team(s) so other teams' keys are
rejected, with a log and metric to surface abuse.

## Usage

```yaml
extensions:
  honeycomb_auth:
    endpoint: https://api.honeycomb.io   # EU: https://api.eu1.honeycomb.io
    # allowed_teams: [my-team-slug]       # default: empty (accept any team)
    # api_key_headers: [x-honeycomb-team, x-hny-team]   # default; first non-empty wins
    # timeout: 3s
    # require_ingest_scope: true          # require api_key_access.events
    # enrich: true                        # inject team/environment into client.Info.Auth
    # cache:
    #   ttl: 5m                           # positive cache (also key-revocation latency)
    #   negative_ttl: 30s                 # invalid-key cache
    #   stale_ttl: 1h                     # serve last-good result if /1/auth is down
    #   max_keys: 10000

receivers:
  otlp:
    protocols:
      grpc:
        auth:
          authenticator: honeycomb_auth
      http:
        auth:
          authenticator: honeycomb_auth

service:
  extensions: [honeycomb_auth]
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
```

## Configuration

| Field | Default | Description |
|---|---|---|
| `endpoint` | `https://api.honeycomb.io` | Honeycomb API base for `/1/auth`. Use the EU base for EU teams. |
| `allowed_teams` | `[]` | Team slugs whose keys are accepted. Empty accepts any team. A valid key from another team is rejected as if invalid (the response does not reveal why), with a Warn log and a `team_not_allowed` metric count. Matching is case-insensitive on the `/1/auth` team slug. |
| `api_key_headers` | `[x-honeycomb-team, x-hny-team]` | Headers to read the ingest key from, in order; first non-empty wins. The outbound `/1/auth` call always uses `x-honeycomb-team`. |
| `timeout` | `3s` | Per-call timeout for `/1/auth`. |
| `require_ingest_scope` | `true` | Reject keys without `api_key_access.events`. |
| `enrich` | `true` | Inject `honeycomb.team`/`honeycomb.environment` (+ slugs) into `client.Info.Auth`. |
| `cache.ttl` | `5m` | Positive-result cache TTL. Upper bound on how long a revoked key keeps working. |
| `cache.negative_ttl` | `30s` | Invalid-key cache TTL (also the retry interval while serving stale). Keep short so a rotated key recovers quickly. |
| `cache.stale_ttl` | `1h` | How long past a successful validation the last-good result may be served if `/1/auth` is unreachable at refresh time. `0` disables stale serving. |
| `cache.max_keys` | `10000` | Max cached keys (LRU). |

`Authenticate` runs on the receive hot path; results are cached (positive + negative TTLs) with a
singleflight so a burst of first-time requests for one key makes a single `/1/auth` call. The
`allowed_teams` check runs per request against the cached result, so rejected teams cost no extra
`/1/auth` traffic. Outbound calls never follow redirects (the ingest key would otherwise be
forwarded to the redirect target).

### Behavior during a `/1/auth` outage

There is no fail-open option: an unauthenticated request is never let through. Instead, when
`/1/auth` is unreachable, keys validated within the last `cache.stale_ttl` keep their last-good
result (including the team check and enrichment, since the full cached response is reused), so
established senders are unaffected. Only keys with no recent validation are rejected until the
backend recovers. Stale results are re-validated every `cache.negative_ttl`, and revert to normal
caching on the first success. Invalid-key verdicts are never served stale.

## Telemetry

The extension emits one self-telemetry counter through the Collector's internal metrics:

| Metric | Type | Attributes |
|---|---|---|
| `otelcol_honeycomb_auth.authentications` (Prometheus: `otelcol_honeycomb_auth_authentications`) | counter | `outcome`: `valid`, `valid_stale`, `missing_header`, `invalid_key`, `team_not_allowed`, `no_ingest_scope`, `backend_error` |

Every `Authenticate` call records exactly one count. Alert on `team_not_allowed` to spot a
collector being used with another team's keys, and on `valid_stale`/`backend_error` for `/1/auth`
health. Per-request Warn logs (team mismatch, stale serving) are sampled (at most a handful per
10s) so an abuse flood cannot drown the collector's own logs; the counter is the reliable signal.

### Downstream use of the resolved environment

When `enrich` is on, a processor can read `client.FromContext(ctx).Auth.GetAttribute("honeycomb.environment")`.
Note: if you need the environment to reach the exporter, copy it onto resource attributes before the
`batch` processor (batching groups by context, which can drop per-request auth data downstream).

## Development

```bash
make test        # unit tests (mock /1/auth)
make lint
make generate    # mdatagen from metadata.yaml
make example     # build + run the example distro (see example/)
```

Prior art this borrows from: Refinery's `/1/auth` + environment cache, and Elastic's `apikeyauth`
extension (external validation + TTL cache).

## License

Apache-2.0.
