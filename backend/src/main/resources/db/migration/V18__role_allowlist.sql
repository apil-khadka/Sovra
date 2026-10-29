-- Hardening: close the role set at rest.
--
-- Java validates on write (ServiceAccountService, BffLoginService) and
-- parses on read (Role.parseAll), but raw SQL or a future writer could
-- still store a typo that fails open (a misspelled BFF privileged role
-- silently skips the hardware-AMR gate) or fails confusingly (an
-- unknown registry role can never authorize anything, as PLANNER
-- proved). These CHECKs reject anything outside the five known roles,
-- matching dev.sovra.authz.Role exactly.
--
-- Existing rows validate during ADD CONSTRAINT (no NOT VALID): every
-- writer already constrains values, and the demo seed inserts no
-- identity rows.

ALTER TABLE service_account
  ADD CONSTRAINT service_account_roles_known CHECK (
    roles <@ ARRAY['TENANT_MEMBER','ISSUER_OPS','RP_CLIENT','TRUST_ADMIN','AUDIT_READER']::TEXT[]);

ALTER TABLE human_membership
  ADD CONSTRAINT human_membership_roles_known CHECK (
    roles <@ ARRAY['TENANT_MEMBER','ISSUER_OPS','RP_CLIENT','TRUST_ADMIN','AUDIT_READER']::TEXT[]);
