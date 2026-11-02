package dev.sovra.audit;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraPostgresBase;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import dev.sovra.authz.Role;
import dev.sovra.tenancy.TenantContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Denial durability under contention (PROD-007): sixteen
 * simultaneous {@code REQUIRES_NEW} denial audits — more than the
 * pool of ten — must all land. Each denial owns its connection
 * briefly; bursts wait milliseconds, never lose rows.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class DenialContentionTests extends SovraPostgresBase {

  @Autowired AuditService audit;

  JdbcTemplate owner;
  UUID tenantId;

  @BeforeEach
  void setup() {
    owner = new JdbcTemplate(ownerDataSource());
    owner.update(
        "INSERT INTO tenant (slug, display_name) VALUES ('denial-load', 'Denial load')"
            + " ON CONFLICT (slug) DO NOTHING");
    tenantId = owner.queryForObject(
        "SELECT id FROM tenant WHERE slug = 'denial-load'", UUID.class);
    owner.update("DELETE FROM audit_event WHERE tenant_id = ?", tenantId);
  }

  @Test
  void concurrentDenialsAllPersist() throws Exception {
    int racers = 16;
    ExecutorService pool = Executors.newFixedThreadPool(racers);
    try {
      List<Future<?>> futures = new ArrayList<>();
      for (int i = 0; i < racers; i++) {
        Callable<?> denial = () -> {
          TenantContext.set(new ServiceAccountPrincipal(
              UUID.randomUUID(), tenantId, "load", Set.of(Role.AUDIT_READER)));
          try {
            audit.recordDenial(
                new ServiceAccountPrincipal(
                    UUID.randomUUID(), tenantId, "load", Set.of(Role.AUDIT_READER)),
                Action.DECIDE_CONSENT,
                new ResourceRef("proof_request", "load-" + Thread.currentThread().threadId(),
                    Optional.of(tenantId)),
                ReasonCode.MISSING_ROLE,
                1);
            return null;
          } finally {
            TenantContext.clear();
          }
        };
        futures.add(pool.submit(denial));
      }
      for (Future<?> future : futures) {
        future.get();
      }
    } finally {
      pool.shutdownNow();
    }
    Integer rows = owner.queryForObject(
        "SELECT COUNT(*) FROM audit_event WHERE tenant_id = ?", Integer.class, tenantId);
    assertThat(rows).isEqualTo(racers);
  }
}
