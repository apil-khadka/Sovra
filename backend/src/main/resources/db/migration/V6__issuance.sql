-- SOV-009: issuer-scoped issuance and constrained signing.
--
-- issuer_signing_key names the keys a signer may use. Rows are
-- append-only for the app role (no UPDATE/DELETE): the first writer
-- wins on the primary key, so a registered key cannot be shadowed by a
-- later INSERT, and registration alone grants nothing — the signer
-- refuses any key whose private half it does not hold.
-- credential_artifact rows are immutable except for terminal revocation
-- (column-level UPDATE on status columns only). Idempotency mappings
-- expire after 24 hours (SOV-001 OD-06); the credential rows they point
-- to live on, and a reused key after expiry mints a new credential.

CREATE TABLE IF NOT EXISTS issuer_signing_key (
  issuer_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  key_version INT NOT NULL CHECK (key_version > 0),
  public_key_jwk JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'REVOKED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (issuer_id, key_id, key_version)
);

CREATE TABLE IF NOT EXISTS credential_artifact (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  issuer_id TEXT NOT NULL,
  vct TEXT NOT NULL,
  holder_thumbprint TEXT NOT NULL,
  key_ref TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL DEFAULT 'VALID' CHECK (status IN ('VALID', 'REVOKED')),
  status_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  artifact TEXT NOT NULL,
  trust_snapshot_version BIGINT NOT NULL,
  created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issuance_idempotency (
  tenant_id UUID NOT NULL REFERENCES tenant (id),
  idempotency_key TEXT NOT NULL,
  credential_id UUID NOT NULL REFERENCES credential_artifact (id),
  request_hash TEXT NOT NULL,
  response_body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, idempotency_key)
);

ALTER TABLE credential_artifact ENABLE ROW LEVEL SECURITY;
ALTER TABLE issuance_idempotency ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON credential_artifact;
CREATE POLICY tenant_isolation ON credential_artifact
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());
DROP POLICY IF EXISTS tenant_isolation ON issuance_idempotency;
CREATE POLICY tenant_isolation ON issuance_idempotency
  USING (tenant_id = app_tenant())
  WITH CHECK (tenant_id = app_tenant());

GRANT SELECT, INSERT ON issuer_signing_key TO sovra_app;
GRANT SELECT, INSERT ON credential_artifact TO sovra_app;
GRANT UPDATE (status, status_updated_at) ON credential_artifact TO sovra_app;
GRANT SELECT, INSERT, DELETE ON issuance_idempotency TO sovra_app;

-- Genesis: trust snapshot v1 authorizes the synthetic issuer only. The
-- key is the P-256 scalar 1 (public half is the generator point), held
-- in signer memory and labelled non-production in code, config, and
-- logs. Production replaces this snapshot through the normal two-person
-- flow; activation only moves forward, so v1 can only be superseded,
-- never edited. Two distinct system identities keep the maker/checker
-- shape even for the seed.
INSERT INTO issuer_signing_key (issuer_id, key_id, key_version, public_key_jwk, status)
VALUES (
  'https://sovra.example/issuers/synth-1',
  'synth-1',
  1,
  '{"kty":"EC","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","kid":"synth-1"}',
  'ACTIVE'
);

INSERT INTO trust_snapshot (created_by, note)
VALUES (
  'synthetic-bootstrap',
  'genesis: synthetic issuer only; production replaces this snapshot through the two-person flow'
);

INSERT INTO issuer_record (
  snapshot_version, issuer_id, display_name, scope, credential_types,
  key_id, public_key_jwk, valid_from, valid_through, status
)
VALUES (
  currval('trust_snapshot_version_seq'),
  'https://sovra.example/issuers/synth-1',
  'Synthetic development issuer (non-production)',
  'synthetic-only',
  ARRAY['https://sovra.example/vct/adult-status/1'],
  'synth-1',
  '{"kty":"EC","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","kid":"synth-1"}',
  now(),
  now() + INTERVAL '10 years',
  'ACTIVE'
);

INSERT INTO trust_change_proposal (snapshot_version, proposed_by)
VALUES (currval('trust_snapshot_version_seq'), 'synthetic-bootstrap');

INSERT INTO trust_proposal_decision (proposal_id, approved_by)
VALUES (
  (SELECT id FROM trust_change_proposal
   WHERE snapshot_version = currval('trust_snapshot_version_seq')),
  'synthetic-checker'
);

INSERT INTO trust_snapshot_activation (snapshot_version, activated_by)
VALUES (currval('trust_snapshot_version_seq'), 'synthetic-activator');
