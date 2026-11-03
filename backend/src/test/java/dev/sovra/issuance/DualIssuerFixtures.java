package dev.sovra.issuance;

import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.guard.ApprovedSchemas;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.trust.IssuerStatus;
import dev.sovra.trust.TrustService;
import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.ObjectMapper;

/**
 * Dual-issuer trust fixture for governed discovery tests. Proposes and
 * activates a snapshot authorizing BOTH synthetic issuers through the real
 * two-person flow (distinct maker/checker accounts): synth-1 keeps the
 * legacy adult-status type only, synth-2 attests the mapped fjord/harbor
 * types plus the explicitly incompatible employment-tenure type for
 * negative discovery. The synth-2 key is P-256 scalar 3 (3G), computed
 * here so the trust proposal carries the correct public JWK; signing
 * itself in single-JVM tests goes through {@link DualIssuerTestDouble}
 * (labelled test double, not independent authority).
 */
public final class DualIssuerFixtures {

  public static final String ISSUER_2 = LocalDevSigner.SECOND_ISSUER_ID;

  private DualIssuerFixtures() {}

  /**
   * Activates a dual-issuer snapshot unless the current one already
   * authorizes both issuers with the expected type lists, and returns the
   * governing version. Idempotent across tests sharing one container.
   */
  public static long ensureDualIssuers(
      JdbcTemplate owner, TrustService trust, ObjectMapper mapper) throws Exception {
    var current = trust.currentSnapshot();
    if (current.isPresent() && authorizesBoth(current.get(), Instant.now())) {
      return current.get().version();
    }
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
    Map<String, Object> genesis = owner.queryForMap(
        "SELECT issuer_id, display_name, scope, credential_types, key_id, public_key_jwk"
            + " FROM issuer_record WHERE snapshot_version ="
            + " (SELECT MIN(snapshot_version) FROM trust_snapshot_activation)"
            + " AND issuer_id = ?",
        IssuanceFixtures.ISSUER_ID);
    TestAccount maker = TestAccounts.create(owner, "dual-maker", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "dual-checker", Set.of("TRUST_ADMIN"));
    Instant now = Instant.now();
    ECParameterSpec params = dev.sovra.crypto.P256.params();
    ECPoint secondPoint = addPoint(
        doublePoint(params.getGenerator(), params), params.getGenerator(), params);
    Map<String, String> secondJwk = new LinkedHashMap<>();
    secondJwk.put("kty", "EC");
    secondJwk.put("crv", "P-256");
    secondJwk.put("x", dev.sovra.crypto.P256.base64UrlUnsigned(secondPoint.getAffineX()));
    secondJwk.put("y", dev.sovra.crypto.P256.base64UrlUnsigned(secondPoint.getAffineY()));
    secondJwk.put("kid", "synth-2");
    var input = new TrustService.ProposalInput(
        List.of(
            new TrustService.IssuerInput(
                (String) genesis.get("issuer_id"),
                (String) genesis.get("display_name"),
                (String) genesis.get("scope"),
                List.of((String[]) ((java.sql.Array) genesis.get("credential_types")).getArray()),
                (String) genesis.get("key_id"),
                1,
                mapper.readTree(String.valueOf(genesis.get("public_key_jwk"))),
                now.minusSeconds(60),
                now.plus(java.time.Duration.ofDays(3650)),
                "ACTIVE"),
            new TrustService.IssuerInput(
                ISSUER_2,
                "Synthetic second issuer (non-production)",
                "synthetic-only",
                List.of(
                    ApprovedSchemas.FJORD_VCT,
                    ApprovedSchemas.HARBOR_VCT,
                    ApprovedSchemas.EMPLOYMENT_VCT),
                "synth-2",
                1,
                mapper.readTree(mapper.writeValueAsString(secondJwk)),
                now.minusSeconds(60),
                now.plus(java.time.Duration.ofDays(3650)),
                "ACTIVE")),
        List.of());
    TrustService.ProposalResult result = asCall(maker,
        () -> trust.propose(asPrincipal(maker), input, "test: authorize dual synthetic issuers"));
    asRun(checker, () -> trust.approve(asPrincipal(checker), result.proposalId()));
    asRun(checker, () -> trust.activate(asPrincipal(checker), result.version()));
    return result.version();
  }

  public static boolean authorizesBoth(TrustService.SnapshotView snapshot, Instant now) {
    boolean first = snapshot.issuers().stream().anyMatch(issuer ->
        IssuanceFixtures.ISSUER_ID.equals(issuer.issuerId())
            && "ACTIVE".equals(issuer.status())
            && !issuer.validFrom().isAfter(now)
            && !issuer.validThrough().isBefore(now)
            && issuer.credentialTypes().contains(IssuanceFixtures.ADULT_VCT));
    boolean second = snapshot.issuers().stream().anyMatch(issuer ->
        ISSUER_2.equals(issuer.issuerId())
            && "ACTIVE".equals(issuer.status())
            && !issuer.validFrom().isAfter(now)
            && !issuer.validThrough().isBefore(now)
            && issuer.credentialTypes().containsAll(List.of(
                ApprovedSchemas.FJORD_VCT,
                ApprovedSchemas.HARBOR_VCT,
                ApprovedSchemas.EMPLOYMENT_VCT)));
    return first && second;
  }

  private static <T> T asCall(TestAccount account, java.util.function.Supplier<T> work) {
    TenantContext.set(asPrincipal(account));
    try {
      return work.get();
    } finally {
      TenantContext.clear();
    }
  }

  private static void asRun(TestAccount account, Runnable work) {
    TenantContext.set(asPrincipal(account));
    try {
      work.run();
    } finally {
      TenantContext.clear();
    }
  }

  private static ServiceAccountPrincipal asPrincipal(TestAccount account) {
    return new ServiceAccountPrincipal(
        account.accountId(), account.tenantId(), account.name(), account.roles());
  }

  private static ECPoint doublePoint(ECPoint p, ECParameterSpec params) {
    BigInteger prime =
        ((java.security.spec.ECFieldFp) params.getCurve().getField()).getP();
    BigInteger a = params.getCurve().getA();
    BigInteger x = p.getAffineX();
    BigInteger y = p.getAffineY();
    BigInteger slope = x.multiply(x).multiply(BigInteger.valueOf(3)).add(a)
        .multiply(y.multiply(BigInteger.TWO).modInverse(prime)).mod(prime);
    BigInteger rx = slope.multiply(slope).subtract(x.multiply(BigInteger.TWO)).mod(prime);
    BigInteger ry = slope.multiply(x.subtract(rx)).subtract(y).mod(prime);
    return new ECPoint(rx, ry);
  }

  private static ECPoint addPoint(ECPoint p, ECPoint q, ECParameterSpec params) {
    BigInteger prime =
        ((java.security.spec.ECFieldFp) params.getCurve().getField()).getP();
    BigInteger slope = q.getAffineY().subtract(p.getAffineY())
        .multiply(q.getAffineX().subtract(p.getAffineX()).modInverse(prime)).mod(prime);
    BigInteger rx = slope.multiply(slope)
        .subtract(p.getAffineX()).subtract(q.getAffineX()).mod(prime);
    BigInteger ry = slope.multiply(p.getAffineX().subtract(rx))
        .subtract(p.getAffineY()).mod(prime);
    return new ECPoint(rx, ry);
  }
}
