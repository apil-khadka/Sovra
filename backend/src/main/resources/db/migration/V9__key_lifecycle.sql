-- SOV-012: freshness, revocation, and key-compromise lifecycle.
--
-- Snapshots pin exact key versions: issuer_record gains key_version, so a
-- rotation (new key identifier, per SOV-001 "replacement needs a new
-- identifier") or a same-id re-registration is authorized explicitly by the
-- two-person snapshot flow. Existing rows backfill to version 1, matching
-- the genesis registry.
--
-- Key compromise and retirement are INSERT-only rows in
-- issuer_key_revocation: the app role cannot UPDATE or DELETE them, so a
-- revocation is terminal by grants (the key analogue of INV-04) and
-- concurrent revokes reconcile on the primary key. The signing-key
-- registry itself stays append-only.
--
-- credential_artifact gains a status_version bumped on every terminal
-- revocation, and verification_decision records the key reference and
-- status version behind each decision next to the trust snapshot
-- version, so every decision carries its actual authority/key/status
-- evidence versions (SOV-012 AC3).

ALTER TABLE issuer_record ADD COLUMN IF NOT EXISTS key_version INT NOT NULL DEFAULT 1
  CHECK (key_version > 0);

CREATE TABLE IF NOT EXISTS issuer_key_revocation (
  issuer_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  key_version INT NOT NULL CHECK (key_version > 0),
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_by TEXT NOT NULL,
  reason TEXT NOT NULL
    CHECK (char_length(reason) BETWEEN 1 AND 256),
  PRIMARY KEY (issuer_id, key_id, key_version)
);

ALTER TABLE credential_artifact ADD COLUMN IF NOT EXISTS status_version BIGINT NOT NULL DEFAULT 1
  CHECK (status_version > 0);

ALTER TABLE verification_decision ADD COLUMN IF NOT EXISTS key_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE verification_decision ADD COLUMN IF NOT EXISTS status_version BIGINT NOT NULL DEFAULT 0
  CHECK (status_version >= 0);

-- Revocation bumps the status version atomically with the terminal flip.
GRANT UPDATE (status, status_updated_at, status_version) ON credential_artifact TO sovra_app;
GRANT SELECT, INSERT ON issuer_key_revocation TO sovra_app;
