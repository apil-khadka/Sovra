-- SOV-016 retention purge: versions can now reach PURGED, where
-- ciphertext and key material are destroyed but the tombstone
-- (id, version, hash, standing) stays for audit.
ALTER TABLE vault_object_version DROP CONSTRAINT IF EXISTS vault_object_version_status_check;
ALTER TABLE vault_object_version
  ADD CONSTRAINT vault_object_version_status_check
  CHECK (status IN ('VALID', 'DELETED', 'PURGED'));
-- Retention purge zeroes the sealed columns; the grant stays
-- column-scoped, adding only what the purge UPDATE writes.
GRANT UPDATE (wrapped_dek, dek_nonce, content_nonce, ciphertext)
  ON vault_object_version TO sovra_app;
