-- PROD-006: fleet-wide admission budgets.
--
-- rate_limit_bucket holds shared token buckets: one row per
-- (scope, key) with the current token balance and the last update
-- timestamp. Refill and consume happen in a single conditional
-- UPDATE, so the database arbitrates races between replicas and no
-- distributed lock exists. Capacity and rate come from deployment
-- configuration on every call, so retuning needs no migration; a
-- bucket row only carries balance state.
--
-- Keys are quota identities ("tenant:<uuid>", "principal:<uuid>",
-- "anon:login", ...), never request content. Stale rows are safe to
-- delete: an idle bucket recreates full, which is exactly what the
-- token-bucket contract grants an idle consumer anyway.
--
-- Global infrastructure table, like the session store: no tenant
-- row policy applies. Tenant isolation comes from keying, and every
-- key embeds an authenticated id or a coarse anonymous scope.

CREATE TABLE rate_limit_bucket (
  bucket TEXT PRIMARY KEY,
  tokens DOUBLE PRECISION NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX rate_limit_bucket_updated_ix ON rate_limit_bucket (updated_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limit_bucket TO sovra_app;
