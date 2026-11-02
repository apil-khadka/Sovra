# Fleet observability (PROD-011)

## Identity

- `sovra.instance-id` (default: container hostname) names the
  replica; `InstanceIdentity` adds a random 16-hex `bootId` per
  process start. Both ride on `GET /api/health` and
  `GET /api/health/ready`, so load-balanced probes are attributable
  and restarts are distinguishable from stale replicas.
- Every Micrometer metric carries the `instance` tag with the same
  value — the fleet view is the scrape target set, no aggregation
  endpoint needed.

## Management port

- `SOVRA_MANAGEMENT_PORT` (default: disabled). Compose sets 8091 on
  both app replicas; the port is deliberately unpublished —
  reachable inside `sovra-net` and via `docker exec`, never through
  ingress. Production must keep it on a private interface
  (see PROD-002).
- Serves `GET /actuator/health`, `/actuator/info`, `/actuator/prometheus`
  without credentials, gated by socket local-port: the same paths on
  the application port stay behind authentication (401 anonymous).
- `/actuator/info` never exposes environment: the env contributor
  would print secret-bearing variables and stays disabled.

## Correlation

- `CorrelationIdFilter` runs first (before the body-size guard): it
  accepts a caller `X-Request-Id` matching `[A-Za-z0-9_.~\-]{1,128}`,
  else mints a UUID. The id echoes in the response header and sits
  in the logging MDC as `requestId`.
- Error payloads (handler, admission denials, body-too-large) use
  the request id as `correlationId`, falling back to random outside
  a request.
- Audit rows with no explicit domain correlation store the request
  id instead of an empty value, so evidence joins to request logs.
  Explicit correlations still win.

## Scrape checklist

1. Prometheus targets each replica's `:8091/actuator/prometheus`.
2. Alert on `up == 0`, on `/api/health/ready` != 200 per replica,
   and on `bootId` flapping (restart loop).
3. Trace a complaint: `X-Request-Id` from the caller → structured
   logs (`requestId`) → audit `correlation_id` → error payload.
