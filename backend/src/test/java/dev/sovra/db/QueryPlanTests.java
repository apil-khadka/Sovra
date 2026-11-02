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
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class QueryPlanTests extends SovraPostgresBase {

  static final int ROWS = 3_000;

  JdbcTemplate owner;
  UUID tenant;

  @BeforeAll
  void seed() {
    owner = new JdbcTemplate(ownerDataSource());
    // The container is a JVM singleton shared by every suite, and
    // earlier quarantine suites leave rows behind: the feed plan
    // depends on global stats, and no other table references this
    // one, so it starts empty. Finished suites never re-read.
    owner.update("DELETE FROM quarantine_admission");
    owner.update("DELETE FROM tenant WHERE slug = 'query-plan-probe'");
    tenant =
        owner.queryForObject(
            "INSERT INTO tenant (slug, display_name)"
                + " VALUES ('query-plan-probe', 'Query plan probe') RETURNING id",
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
    owner.update(
        "INSERT INTO quarantine_admission (tenant_id, vault_object_id, actual_type,"
            + " size_bytes, content_sha256, status, created_by)"
            + " SELECT ?, ?, 'image/png', 8, decode(md5(g::text), 'hex'),"
            + " CASE WHEN g % 10 = 0 THEN 'QUARANTINED' ELSE 'SCANNING' END, 'plan-agent'"
            + " FROM generate_series(1, ?) g",
        tenant, vault, ROWS);
    owner.execute("ANALYZE verification_decision");
    owner.execute("ANALYZE proof_request");
    owner.execute("ANALYZE credential_artifact");
    owner.execute("ANALYZE audit_event");
    owner.execute("ANALYZE quarantine_admission");
  }

  @AfterAll
  void cleanup() {
    owner.update("DELETE FROM verification_decision WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM proof_request WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM credential_artifact WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM audit_event WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM quarantine_admission WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM vault_object WHERE tenant_id = ?", tenant);
    owner.update("DELETE FROM tenant WHERE id = ?", tenant);
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
    assertThat(plan(
            "SELECT id FROM quarantine_admission WHERE tenant_id = '" + tenant + "'"
                + " ORDER BY created_at DESC, id DESC LIMIT 50"))
        .contains("quarantine_admission_tenant_recent_idx")
        .doesNotContain("Seq Scan on quarantine_admission");
    assertThat(plan(
            "SELECT id FROM quarantine_admission WHERE tenant_id = '" + tenant + "'"
                + " AND status = 'QUARANTINED'"
                + " ORDER BY created_at DESC, id DESC LIMIT 50"))
        .contains("quarantine_admission_tenant_status_recent_idx")
        .doesNotContain("Seq Scan on quarantine_admission");
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
