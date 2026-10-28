-- SOV-006: application credential lifecycle grants. The app role
-- mints service accounts, replaces their credentials, and
-- terminally revokes them — all tenant-scoped by query (this table
-- predates RLS; every statement carries its tenant predicate). Roles
-- are immutable after creation: a role change means mint-plus-revoke,
-- which keeps the audit trail explicit. No DELETE, ever.
GRANT INSERT ON service_account TO sovra_app;
GRANT UPDATE (token_prefix, token_hash, expires_at, revoked) ON service_account TO sovra_app;
