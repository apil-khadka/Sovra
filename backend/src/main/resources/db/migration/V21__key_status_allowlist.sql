-- Key standing is a closed set (KeyStatus): ACTIVE at publish,
-- REVOKED terminally. The constraint validates existing rows on
-- creation; both writers already stay inside the set.
ALTER TABLE issuer_signing_key
  ADD CONSTRAINT issuer_signing_key_status_known
  CHECK (status IN ('ACTIVE', 'REVOKED'));
