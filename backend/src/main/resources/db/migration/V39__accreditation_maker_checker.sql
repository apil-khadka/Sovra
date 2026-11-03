-- PROD-015: bind every new accreditation request to the authenticated
-- principal id so a request maker cannot approve or reject their own
-- case through either the machine or BFF authentication chain.
ALTER TABLE accreditation
  ADD COLUMN IF NOT EXISTS requested_by_principal_id UUID;

-- V37 stored the human-readable name only. Recover the stable id from
-- the immutable request audit event where the historical row is still
-- available; unresolved legacy rows use a conservative name fallback
-- in the service until they are closed.
UPDATE accreditation a
SET requested_by_principal_id = (
  SELECT CASE
    WHEN e.actor_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      THEN e.actor_id::uuid
    ELSE NULL
  END
  FROM audit_event e
  WHERE e.tenant_id = a.tenant_id
    AND e.action = 'ACCREDIT_REQUEST'
    AND e.resource_type = 'accreditation'
    AND e.resource_id = a.id::text
  ORDER BY e.occurred_at
  LIMIT 1
)
WHERE a.requested_by_principal_id IS NULL;
