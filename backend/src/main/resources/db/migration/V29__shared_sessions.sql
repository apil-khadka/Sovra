-- PROD-003: shared BFF sessions and atomic unlock challenges.
--
-- SPRING_SESSION / SPRING_SESSION_ATTRIBUTES follow Spring Session's
-- own postgresql schema for the managed version (4.1.x): the column
-- set and indexes below mirror
-- org/springframework/session/jdbc/schema-postgresql.sql from the
-- spring-session-jdbc jar, so upgrades stay comparable. Identifiers
-- are unquoted and fold to lower case, exactly as the stock schema
-- does; the repository issues unquoted SQL to match.
--
-- holder_unlock_challenge holds single-use holder-unlock challenges
-- outside any one replica's memory. The challenge value is a 256-bit
-- random capability; consume is an atomic conditional DELETE, so
-- concurrent unlock submissions on different replicas bind at most
-- once. Rows are meaningless without the holder private key that
-- signs the proof, and expire after five minutes.
--
-- These are global infrastructure tables, not tenant rows: session
-- ids and challenge values are unguessable, membership binding is
-- enforced in SQL, and the session repository uses the plain
-- datasource (never the tenant-pinned wrapper), so no row-level
-- policy applies here. Tenant isolation for the data behind a
-- session still comes from the membership row reloaded per request.

CREATE TABLE SPRING_SESSION (
  PRIMARY_ID CHAR(36) NOT NULL,
  SESSION_ID CHAR(36) NOT NULL,
  CREATION_TIME BIGINT NOT NULL,
  LAST_ACCESS_TIME BIGINT NOT NULL,
  MAX_INACTIVE_INTERVAL INT NOT NULL,
  EXPIRY_TIME BIGINT NOT NULL,
  PRINCIPAL_NAME VARCHAR(100),
  CONSTRAINT SPRING_SESSION_PK PRIMARY KEY (PRIMARY_ID)
);

CREATE UNIQUE INDEX SPRING_SESSION_IX1 ON SPRING_SESSION (SESSION_ID);
CREATE INDEX SPRING_SESSION_IX2 ON SPRING_SESSION (EXPIRY_TIME);
CREATE INDEX SPRING_SESSION_IX3 ON SPRING_SESSION (PRINCIPAL_NAME);

CREATE TABLE SPRING_SESSION_ATTRIBUTES (
  SESSION_PRIMARY_ID CHAR(36) NOT NULL,
  ATTRIBUTE_NAME VARCHAR(200) NOT NULL,
  ATTRIBUTE_BYTES BYTEA NOT NULL,
  CONSTRAINT SPRING_SESSION_ATTRIBUTES_PK PRIMARY KEY (SESSION_PRIMARY_ID, ATTRIBUTE_NAME),
  CONSTRAINT SPRING_SESSION_ATTRIBUTES_FK FOREIGN KEY (SESSION_PRIMARY_ID)
    REFERENCES SPRING_SESSION (PRIMARY_ID) ON DELETE CASCADE
);

CREATE TABLE holder_unlock_challenge (
  challenge TEXT PRIMARY KEY,
  membership_id UUID NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX holder_unlock_challenge_expires_ix
  ON holder_unlock_challenge (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON SPRING_SESSION TO sovra_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON SPRING_SESSION_ATTRIBUTES TO sovra_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON holder_unlock_challenge TO sovra_app;
