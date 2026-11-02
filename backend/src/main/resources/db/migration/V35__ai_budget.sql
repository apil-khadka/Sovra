-- PROD-012: fleet-wide live-AI budget ledger.
--
-- Reservations are atomic across replicas: every live call
-- reserves requests/tokens/concurrency inside one transaction
-- holding the day-row lock, so the database arbitrates quota
-- races and no two replicas can overspend the same budget.
-- The ledger is fleet-global (no tenant RLS); tenant_id on
-- leases is audit-only.
--
-- Outcomes: SETTLED records actual provider usage, REFUNDED
-- returns an unspent reservation, UNCERTAIN burns the estimate
-- (timeouts and unknown outcomes never refund — conservative by
-- construction). The sweeper converts abandoned HELD leases
-- (crashed callers) to UNCERTAIN past expiry.

CREATE TABLE ai_budget_day (
  day DATE PRIMARY KEY,
  request_limit INT NOT NULL CHECK (request_limit >= 0),
  token_limit BIGINT NOT NULL CHECK (token_limit >= 0),
  concurrency_limit INT NOT NULL CHECK (concurrency_limit >= 0),
  requests_used INT NOT NULL DEFAULT 0 CHECK (requests_used >= 0),
  tokens_used BIGINT NOT NULL DEFAULT 0 CHECK (tokens_used >= 0),
  requests_reserved INT NOT NULL DEFAULT 0 CHECK (requests_reserved >= 0),
  tokens_reserved BIGINT NOT NULL DEFAULT 0 CHECK (tokens_reserved >= 0)
);

CREATE TABLE ai_call_lease (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  day DATE NOT NULL REFERENCES ai_budget_day (day),
  mode TEXT NOT NULL DEFAULT 'live',
  estimated_tokens BIGINT NOT NULL CHECK (estimated_tokens > 0),
  settled_tokens BIGINT,
  state TEXT NOT NULL DEFAULT 'HELD'
    CHECK (state IN ('HELD', 'SETTLED', 'REFUNDED', 'UNCERTAIN')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  settled_at TIMESTAMPTZ
);

CREATE INDEX ai_lease_held_idx ON ai_call_lease (expires_at)
  WHERE state = 'HELD';

GRANT SELECT, INSERT, UPDATE ON ai_budget_day TO sovra_app;
GRANT SELECT, INSERT, UPDATE ON ai_call_lease TO sovra_app;
