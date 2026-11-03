package dev.sovra.db;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraPostgresBase;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * PROD-008: the tenant feed indexes are load-bearing. Each test
 * seeds a few thousand rows, runs ANALYZE, then asserts the real
 * feed SQL plans an index path with no sequential scan. A dropped
 * or superseded index fails here instead of in production.
 *
 * <p>Quarantine needs a representative multi-tenant fixture. The
 * worker-claim partial index {@code quarantine_claim_idx} covers
 * only {@code status = 'QUARANTINED'} ordered by {@code created_at};
 * a single-tenant probe with identical timestamps makes a backward
 * scan of that partial index plus a {@code Filter: tenant_id}
 * look as cheap as the tenant-leading feed index, and the planner
 * flips between them on trivial stats differences (observed:
 * full-suite red, isolated green). Production holds many tenants,
 * so the partial-index path is unbounded per tenant: it must scan
 * every tenant's recent QUARANTINED rows to find one tenant's
 * page. The noise tenant below (thousands of recent QUARANTINED
 * rows, strictly newer than the probe's) reproduces that shape in
 * miniature and forces the planner to prefer the tenant-leading
 * {@code quarantine_admission_tenant_status_recent_idx}, whose
 * {@code Index Cond} bounds the feed to the tenant's own rows.
 * The claim index stays correct for the worker's global
 * oldest-first claim ({@code QuarantineWorker}), which is a
 * different query and is not asserted here.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class QueryPlanTests extends SovraPostgresBase {

  static final int ROWS = 3_000;
  static final int NOISE_ROWS = 3_000;

  JdbcTemplate owner;
  UUID tenant;
  UUID noiseTenant;

  @BeforeAll
  void seed() {
    owner = new JdbcTemplate(ownerDataSource());
    // Tenant-scoped reset only: the container is a JVM singleton
    // shared by every suite, and earlier suites' leftover rows stay
    // (they add multi-tenant realism). Only our own slugs are
    // removed, for rerun idempotence after a crashed run.
    clearProbeRows();
    tenant =
        owner.queryForObject(
            "INSERT INTO tenant (slug, display_name)"
                + " VALUES ('query-plan-probe', 'Query plan probe') RETURNING id",
            UUID.class);
    noiseTenant =
        owner.queryForObject(
            "INSERT INTO tenant (slug, display_name)"
                + " VALUES ('query-plan-noise', 'Query plan noise') RETURNING id",
            UUID.class);
    UUID credential =
        owner.queryForObject(
            "INSERT INTO credential_artifact (tenant_id, issuer_id, vct, holder_thumbprint,"
                + " key_ref, expires_at, artifact, trust_snapshot_version, created_by)"
                + " VALUES (?, 'issuer-1', 'AgeOver18', 'thumb-probe', 'key-1',"
                + " now() + interval '1 year', '{}', 1, 'plan-test') RETURNING id",
            UUID.class,
            tenant);
    UUID request =
        owner.queryForObject(
            "INSERT INTO proof_request (tenant_id, credential_id, rp_id, audience, purpose,"
                + " claims, plan_hash, challenge, holder_thumbprint, expires_at,"
                + " trust_snapshot_version, created_by)"
                + " VALUES (?, ?, 'rp-1', 'aud-1', 'age-check', '{}',"
                + " md5('a') || md5('b'), 'challenge-' || md5('c'), 'thumb-probe',"
                + " now() + interval '1 hour', 1, 'plan-test') RETURNING id",
            UUID.class,
            tenant,
            credential);
    UUID vault =
        owner.queryForObject(
            "INSERT INTO vault_object (tenant_id, issuer_id, created_by)"
                + " VALUES (?, 'issuer-1', 'plan-test') RETURNING id",
            UUID.class,
            tenant);
    UUID noiseVault =
        owner.queryForObject(
            "INSERT INTO vault_object (tenant_id, issuer_id, created_by)"
                + " VALUES (?, 'issuer-1', 'plan-noise') RETURNING id",
            UUID.class,
            noiseTenant);
    owner.update(
        "INSERT INTO verification_decision (tenant_id, request_id, credential_id, nonce,"
            + " request_hash, rp_id, audience, outcome, reason_code, response_body,"
            + " trust_snapshot_version, decided_by)"
            + " SELECT ?, ?, ?, 'nonce-' || md5(g::text), md5(g::text), 'rp-1', 'aud-1',"
            + " 'ACCEPTED', 'ok', '{}', 1,"
            + " CASE WHEN g % 10 = 0 THEN 'plan-agent' ELSE 'plan-other' END"
            + " FROM generate_series(1, ?) g",
        tenant,
        request,
        credential,
        ROWS);
    owner.update(
        "INSERT INTO proof_request (tenant_id, credential_id, rp_id, audience, purpose,"
            + " claims, plan_hash, challenge, holder_thumbprint, expires_at,"
            + " trust_snapshot_version, created_by)"
            + " SELECT ?, ?, 'rp-1', 'aud-1', 'age-check', '{}',"
            + " md5(g::text) || md5('p' || g::text), 'challenge-' || md5('q' || g::text),"
            + " 'thumb-probe', now() + interval '1 hour', 1, 'plan-test'"
            + " FROM generate_series(1, ?) g",
        tenant,
        credential,
        ROWS);
    owner.update(
        "INSERT INTO credential_artifact (tenant_id, issuer_id, vct, holder_thumbprint,"
            + " key_ref, expires_at, artifact, trust_snapshot_version, created_by)"
            + " SELECT ?, 'issuer-1', 'AgeOver18', 'thumb-probe', 'key-' || g::text,"
            + " now() + interval '1 year', '{}', 1, 'plan-test'"
            + " FROM generate_series(1, ?) g",
        tenant,
        ROWS);
    owner.update(
        "INSERT INTO audit_event (tenant_id, actor_type, actor_id, action, resource_type,"
            + " resource_id, decision, reason_code, policy_version)"
            + " SELECT ?, 'service', 'plan-agent', 'READ', 'probe', '', 'ALLOW', 'ok', 1"
            + " FROM generate_series(1, ?) g",
        tenant, ROWS);
    // Probe feed rows: varied timestamps (oldest first by g),
    // 10% QUARANTINED. All timestamps sit at least two hours in
    // the past, strictly older than every noise row below.
    owner.update(
        "INSERT INTO quarantine_admission (tenant_id, vault_object_id, actual_type,"
            + " size_bytes, content_sha256, status, created_by, created_at)"
            + " SELECT ?, ?, 'image/png', 8, decode(md5(g::text), 'hex'),"
            + " CASE WHEN g % 10 = 0 THEN 'QUARANTINED' ELSE 'SCANNING' END, 'plan-agent',"
            + " now() - interval '2 hours' - (g || ' seconds')::interval"
            + " FROM generate_series(1, ?) g",
        tenant, vault, ROWS);
    // Cross-tenant noise: recent QUARANTINED rows that a global
    // partial-index scan must skip through (up to NOISE_ROWS
    // filtered rows) before reaching one probe row, while the
    // tenant-leading index seeks the probe's rows directly.
    owner.update(
        "INSERT INTO quarantine_admission (tenant_id, vault_object_id, actual_type,"
            + " size_bytes, content_sha256, status, created_by, created_at)"
            + " SELECT ?, ?, 'image/png', 8, decode(md5('n' || g::text), 'hex'),"
            + " 'QUARANTINED', 'plan-noise', now() - (g || ' seconds')::interval"
            + " FROM generate_series(1, ?) g",
        noiseTenant, noiseVault, NOISE_ROWS);
    owner.execute("ANALYZE verification_decision");
    owner.execute("ANALYZE proof_request");
    owner.execute("ANALYZE credential_artifact");
    owner.execute("ANALYZE audit_event");
    owner.execute("ANALYZE quarantine_admission");
  }

  @AfterAll
  void cleanup() {
    clearProbeRows();
  }

  /** Deletes only this class's slugs; sibling suites' rows stay. */
  private void clearProbeRows() {
    owner.update(
        "DELETE FROM verification_decision WHERE tenant_id IN"
            + " (SELECT id FROM tenant WHERE slug IN ('query-plan-probe', 'query-plan-noise'))");
    owner.update(
        "DELETE FROM proof_request WHERE tenant_id IN"
            + " (SELECT id FROM tenant WHERE slug IN ('query-plan-probe', 'query-plan-noise'))");
    owner.update(
        "DELETE FROM credential_artifact WHERE tenant_id IN"
            + " (SELECT id FROM tenant WHERE slug IN ('query-plan-probe', 'query-plan-noise'))");
    owner.update(
        "DELETE FROM audit_event WHERE tenant_id IN"
            + " (SELECT id FROM tenant WHERE slug IN ('query-plan-probe', 'query-plan-noise'))");
    owner.update(
        "DELETE FROM quarantine_admission WHERE tenant_id IN"
            + " (SELECT id FROM tenant WHERE slug IN ('query-plan-probe', 'query-plan-noise'))");
    owner.update(
        "DELETE FROM vault_object WHERE tenant_id IN"
            + " (SELECT id FROM tenant WHERE slug IN ('query-plan-probe', 'query-plan-noise'))");
    owner.update("DELETE FROM tenant WHERE slug IN ('query-plan-probe', 'query-plan-noise')");
  }

  @Test
  void decisionFeedUsesTenantRecentIndex() {
    assertThat(plan(
            "SELECT id FROM verification_decision WHERE tenant_id = '" + tenant + "'"
                + " ORDER BY decided_at DESC, id DESC LIMIT 50"))
        .contains("verification_decision_tenant_recent_idx")
        .doesNotContain("Seq Scan on verification_decision");
  }

  @Test
  void decisionScopedFeedUsesAgentIndex() {
    assertThat(plan(
            "SELECT id FROM verification_decision WHERE tenant_id = '" + tenant + "'"
                + " AND decided_by = 'plan-agent'"
                + " ORDER BY decided_at DESC, id DESC LIMIT 50"))
        .contains("verification_decision_tenant_agent_recent_idx")
        .doesNotContain("Seq Scan on verification_decision");
  }

  @Test
  void proofHolderFeedUsesIndex() {
    assertThat(plan(
            "SELECT id FROM proof_request WHERE tenant_id = '" + tenant + "'"
                + " AND holder_thumbprint = 'thumb-probe'"
                + " ORDER BY created_at DESC, id DESC LIMIT 50"))
        .contains("proof_request_holder_recent_idx")
        .doesNotContain("Seq Scan on proof_request");
  }

  @Test
  void credentialHolderFeedUsesIndex() {
    assertThat(plan(
            "SELECT id FROM credential_artifact WHERE tenant_id = '" + tenant + "'"
                + " AND holder_thumbprint = 'thumb-probe'"
                + " ORDER BY issued_at DESC, id DESC LIMIT 50"))
        .contains("credential_artifact_holder_recent_idx")
        .doesNotContain("Seq Scan on credential_artifact");
  }

  @Test
  void auditFeedUsesTenantRecentIndex() {
    assertThat(plan(
            "SELECT id FROM audit_event WHERE tenant_id = '" + tenant + "'"
                + " ORDER BY occurred_at DESC, id DESC LIMIT 50"))
        .contains("audit_event_tenant_recent_idx")
        .doesNotContain("Seq Scan on audit_event");
  }

  @Test
  void quarantineFeedsUseIndexes() {
    // Index Cond (not Filter) proves the feed is bounded to the
    // tenant's rows inside the index; a Filter on tenant_id would
    // scan other tenants' rows first (the quarantine_claim_idx
    // failure mode) and grow with total table size.
    assertThat(plan(
            "SELECT id FROM quarantine_admission WHERE tenant_id = '" + tenant + "'"
                + " ORDER BY created_at DESC, id DESC LIMIT 50"))
        .contains("quarantine_admission_tenant_recent_idx")
        .contains("Index Cond")
        .doesNotContain("Seq Scan on quarantine_admission")
        .doesNotContain("Filter:");
    assertThat(plan(
            "SELECT id FROM quarantine_admission WHERE tenant_id = '" + tenant + "'"
                + " AND status = 'QUARANTINED'"
                + " ORDER BY created_at DESC, id DESC LIMIT 50"))
        .contains("quarantine_admission_tenant_status_recent_idx")
        .contains("Index Cond")
        .doesNotContain("Seq Scan on quarantine_admission")
        .doesNotContain("Filter:");
  }

  @Test
  void enrollmentIndexesExist() {
    // Enrollment parents (vault + extraction + service account) make
    // bulk seeding expensive, so the queue indexes are guarded by
    // presence: a dropped index fails here.
    assertThat(indexesOn("enrollment"))
        .contains("enrollment_tenant_recent_idx", "enrollment_tenant_state_recent_idx");
  }

  private String plan(String sql) {
    List<String> lines = owner.query("EXPLAIN (COSTS OFF) " + sql,
        (rs, row) -> rs.getString(1));
    return String.join("\n", lines);
  }

  private List<String> indexesOn(String table) {
    return owner.query(
        "SELECT indexname FROM pg_indexes WHERE tablename = ?",
        (rs, row) -> rs.getString(1), table);
  }
}
