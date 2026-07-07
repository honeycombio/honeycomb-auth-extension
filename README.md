# honeycomb-auth-extension

An OpenTelemetry Collector [server authenticator](https://opentelemetry.io/docs/collector/configuration/#authentication)
extension that validates the incoming `x-honeycomb-team` ingest key against Honeycomb's `/1/auth`
endpoint, caches the result, and (optionally) injects the resolved team/environment into
`client.Info.Auth` for downstream components.

Because it runs inside the Collector, it is infrastructure-agnostic: the auth check travels with the
collector and works the same wherever it runs (any cloud, on-prem, or a customer-hosted collector),
with no dependency on a particular load balancer, API gateway, or managed edge service.

## Why

Honeycomb ingest keys are opaque, so validating one means calling `/1/auth` (a 401 means the key is
invalid/revoked; the response body carries the team, environment, and `api_key_access` scopes). No
stock Collector auth extension does an external-API lookup (`bearertokenauth` only compares static
tokens), and load-balancer/edge auth can't call an arbitrary API to validate an opaque key. This
extension fills that gap, and doubles as an environment resolver (same call).

## Usage

```yaml
extensions:
  honeycombauth:
    endpoint: https://api.honeycomb.io   # EU: https://api.eu1.honeycomb.io
    # api_key_headers: [x-honeycomb-team, x-hny-team]   # default; first non-empty wins
    # timeout: 3s
    # fail_closed: true                   # reject if /1/auth is unreachable
    # require_ingest_scope: true          # require api_key_access.events
    # enrich: true                        # inject team/environment into client.Info.Auth
    # cache:
    #   ttl: 5m                           # positive cache (also key-revocation latency)
    #   negative_ttl: 30s                 # invalid-key cache
    #   max_keys: 10000

receivers:
  otlp:
    protocols:
      grpc:
        auth:
          authenticator: honeycombauth
      http:
        auth:
          authenticator: honeycombauth

service:
  extensions: [honeycombauth]
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
```

## Configuration

| Field | Default | Description |
|---|---|---|
| `endpoint` | `https://api.honeycomb.io` | Honeycomb API base for `/1/auth`. Use the EU base for EU teams. |
| `api_key_headers` | `[x-honeycomb-team, x-hny-team]` | Headers to read the ingest key from, in order; first non-empty wins. The outbound `/1/auth` call always uses `x-honeycomb-team`. |
| `timeout` | `3s` | Per-call timeout for `/1/auth`. |
| `fail_closed` | `true` | Reject when `/1/auth` is unreachable. Set `false` to fail open (Honeycomb re-validates downstream). |
| `require_ingest_scope` | `true` | Reject keys without `api_key_access.events`. |
| `enrich` | `true` | Inject `honeycomb.team`/`honeycomb.environment` (+ slugs) into `client.Info.Auth`. |
| `cache.ttl` | `5m` | Positive-result cache TTL. Upper bound on how long a revoked key keeps working. |
| `cache.negative_ttl` | `30s` | Invalid-key cache TTL. Keep short so a rotated key recovers quickly. |
| `cache.max_keys` | `10000` | Max cached keys (LRU) per table. |

`Authenticate` runs on the receive hot path; results are cached (positive + negative TTLs) with a
singleflight so a burst of first-time requests for one key makes a single `/1/auth` call.

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
