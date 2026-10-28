-- SOV-036: the evaluated artifact profile is stored evidence. A
-- decision receipt must name the profile that produced it even when a
-- mixed fleet serves reads, so verification_decision gains an immutable
-- profile column alongside the byte-identical response body. Existing
-- rows backfill to the synthetic label they were written under. Table
-- grants are unchanged (SELECT, INSERT for the app role, no
-- UPDATE/DELETE).
ALTER TABLE verification_decision
  ADD COLUMN IF NOT EXISTS profile TEXT NOT NULL
    DEFAULT 'sovra-g1-synthetic/0.2';
