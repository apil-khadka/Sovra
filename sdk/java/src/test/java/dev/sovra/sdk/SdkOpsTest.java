package dev.sovra.sdk;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Ops quickstart (SOV-021): health, readiness, snapshot, identity, alerts, audit. */
class SdkOpsTest extends SdkLiveBase {

  @Test
  void opsQuickstart() throws Exception {
    MachineAccount account = mintAccount("sdk-ops", "ISSUER_OPS,AUDIT_READER");
    try (SovraClient client = clientFor(account.token())) {
      OpsClient.Health health = client.ops.health();
      assertThat(health.status()).isEqualTo("UP");
      OpsClient.ReadinessReport readiness = client.ops.readiness();
      assertThat(readiness.status()).isEqualTo("READY");
      assertThat(readiness.checks()).isNotEmpty();
      OpsClient.WhoAmI whoami = client.ops.whoami();
      assertThat(whoami.roles()).contains("ISSUER_OPS");
      OpsClient.TrustSnapshot snapshot = client.ops.snapshot();
      assertThat(snapshot.version()).isPositive();
      assertThat(snapshot.issuers()).isNotEmpty();
      assertThat(client.ops.alerts()).isNotNull();
      assertThat(client.ops.audit(5, null)).isNotNull();
    }
  }

  @Test
  void auditCursorPassesThroughOpaquely() throws Exception {
    MachineAccount account = mintAccount("sdk-audit", "AUDIT_READER");
    try (SovraClient client = clientFor(account.token())) {
      List<OpsClient.AuditEvent> first = client.ops.audit(2, null);
      assertThat(first.size()).isLessThanOrEqualTo(2);
      if (!first.isEmpty()) {
        OpsClient.AuditEvent last = first.get(first.size() - 1);
        List<OpsClient.AuditEvent> next =
            client.ops.audit(2, OpsClient.cursorFor(last));
        assertThat(next).isNotNull();
        for (OpsClient.AuditEvent row : next) {
          assertThat(row.id()).isNotEqualTo(last.id());
        }
      }
    }
  }
}
