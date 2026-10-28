-- Test-only init: least-privilege role for Testcontainers databases.
-- The password below is a non-secret test credential, never production.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sovra_app') THEN
    CREATE ROLE sovra_app WITH LOGIN PASSWORD 'sovra-app-test';
  ELSE
    ALTER ROLE sovra_app WITH LOGIN PASSWORD 'sovra-app-test';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sovra_quarantine') THEN
    CREATE ROLE sovra_quarantine WITH LOGIN PASSWORD 'sovra-quarantine-test';
  ELSE
    ALTER ROLE sovra_quarantine WITH LOGIN PASSWORD 'sovra-quarantine-test';
  END IF;
END
$$;
