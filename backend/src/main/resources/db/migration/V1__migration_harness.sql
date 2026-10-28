-- SOV-003 bootstrap: proves versioned migrations execute on a clean checkout.
-- Domain tables arrive with the G0 decisions (SOV-001/SOV-002/SOV-004);
-- this table carries no domain semantics.
CREATE TABLE IF NOT EXISTS migration_probe (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  installed_on TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO migration_probe DEFAULT VALUES;
