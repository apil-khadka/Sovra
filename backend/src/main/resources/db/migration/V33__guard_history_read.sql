-- PROD-002: the serve-side schema guard (SchemaValidationGuard)
-- reads the migration history over the least-privilege app role.
-- SELECT only: the serving runtime verifies currency, it never
-- migrates.
GRANT SELECT ON flyway_schema_history TO sovra_app;
