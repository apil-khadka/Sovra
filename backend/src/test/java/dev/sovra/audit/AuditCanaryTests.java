package dev.sovra.audit;

import static org.assertj.core.api.Assertions.assertThat;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import dev.sovra.SovraPostgresBase;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ResourceRef;
import dev.sovra.tenancy.TenantContext;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/** Canary suite: secrets and PII-shaped values must never land in evidence. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AuditCanaryTests extends SovraPostgresBase {

  @Autowired AuditService audit;

  @Autowired ObjectMapper mapper;

  JdbcTemplate owner;

  @BeforeEach
  void setup() {
    owner = new JdbcTemplate(ownerDataSource());
  }

  @AfterEach
  void clear() {
    TenantContext.clear();
  }

  @Test
  void sensitiveKeysAreDroppedAndValuesTruncated() throws Exception {
    TestAccount account = TestAccounts.create(owner, "canary", Set.of("AUDIT_READER"));
    TenantContext.set(
        new ServiceAccountPrincipal(
            account.accountId(), account.tenantId(), account.name(), account.roles()));
    Map<String, String> detail = new LinkedHashMap<>();
    detail.put("token", "sovra_test_CANARYTOKEN");
    detail.put("password", "CANARYPW");
    detail.put("ssn", "CANARY-SSN-11-22-3333");
    detail.put("private_key", "CANARYKEY");
    detail.put("note", "x".repeat(600) + "CANARY_TAIL");
    audit.record(
        TenantContext.require(),
        Action.READ_AUDIT,
        ResourceRef.global("audit", "events"),
        Decision.permit(1),
        "",
        detail);

    Map<String, Object> row = TestAccounts.auditRow(owner, "READ_AUDIT");
    JsonNode stored = mapper.readTree(row.get("detail").toString());
    assertThat(stored.has("token")).isFalse();
    assertThat(stored.has("password")).isFalse();
    assertThat(stored.has("ssn")).isFalse();
    assertThat(stored.has("private_key")).isFalse();
    assertThat(stored.get("note").asText()).hasSize(500);
    assertThat(TestAccounts.allAuditText(owner)).doesNotContain("CANARY");
  }

  @Test
  void sanitizerNeverThrowsOnHostileContent() {
    Map<String, String> hostile = new LinkedHashMap<>();
    hostile.put(null, "null-key");
    hostile.put("ok", null);
    hostile.put("SeCrEt", "mixed-case");
    Map<String, String> clean = audit.sanitize(hostile);
    assertThat(clean).containsEntry("ok", "");
    assertThat(clean.keySet()).doesNotContain("SeCrEt");
  }
}
