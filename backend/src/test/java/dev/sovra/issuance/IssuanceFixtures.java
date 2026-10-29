package dev.sovra.issuance;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.crypto.P256;
import dev.sovra.tenancy.TenantContext;
import dev.sovra.trust.TrustService;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Holder keys, proofs, and synthetic-issuer fixture support for issuance tests. */
public final class IssuanceFixtures {

  public static final String ISSUER_ID = "https://sovra.example/issuers/synth-1";
  public static final String ADULT_VCT = "https://sovra.example/vct/adult-status/1";

  private IssuanceFixtures() {}

  public record HolderKeys(ECPublicKey publicKey, ECPrivateKey privateKey, JsonNode jwk) {}

  public static HolderKeys generateHolder(ObjectMapper mapper) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair pair = generator.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) pair.getPublic();
    Map<String, String> jwk = new LinkedHashMap<>();
    jwk.put("kty", "EC");
    jwk.put("crv", "P-256");
    jwk.put("x", base64UrlUnsigned(pub.getW().getAffineX()));
    jwk.put("y", base64UrlUnsigned(pub.getW().getAffineY()));
    return new HolderKeys(pub, (ECPrivateKey) pair.getPrivate(),
        mapper.readTree(mapper.writeValueAsString(jwk)));
  }

  public static String base64UrlUnsigned(BigInteger value) {
    byte[] raw = value.toByteArray();
    byte[] fixed = new byte[32];
    System.arraycopy(raw, Math.max(0, raw.length - 32), fixed, Math.max(0, 32 - raw.length),
        Math.min(32, raw.length));
    return Base64URL.encode(fixed).toString();
  }

  public static String thumbprint(HolderKeys holder) {
    return P256.thumbprint(
        holder.publicKey().getW().getAffineX(), holder.publicKey().getW().getAffineY());
  }

  /** Holder proof of possession over the issuance proof message. */
  public static String proof(HolderKeys holder, String idempotencyKey, String vct,
      ObjectMapper mapper) throws Exception {
    String message =
        IssuanceService.PROOF_LABEL + "\n" + idempotencyKey + "\n" + vct + "\n"
            + thumbprint(holder) + "\n"
            + "adultOver18=true";
    return proofOver(holder, message, mapper);
  }

  public static String proofOver(HolderKeys holder, String message, ObjectMapper mapper)
      throws Exception {
    String header = Base64URL.encode("{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8))
        .toString();
    String payload =
        Base64URL.encode(message.getBytes(StandardCharsets.UTF_8)).toString();
    Signature signature = Signature.getInstance("SHA256withECDSA");
    signature.initSign(holder.privateKey());
    signature.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
    String proof = Base64URL.encode(ECDSA.transcodeSignatureToConcat(signature.sign(), 64))
        .toString();
    return header + "." + payload + "." + proof;
  }

  public record VerifiedArtifact(JsonNode header, JsonNode claims) {}

  /** Verifies the artifact with Nimbus (independent path from the encoder). */
  public static VerifiedArtifact verify(String artifact, String jwksJson, ObjectMapper mapper)
      throws Exception {
    JsonNode jwks = mapper.readTree(jwksJson);
    String keyJson = mapper.writeValueAsString(jwks.get("keys").get(0));
    ECKey key = (ECKey) ECKey.parse(keyJson);
    JWSObject parsed = JWSObject.parse(artifact);
    if (!parsed.verify(new ECDSAVerifier(key))) {
      throw new IllegalStateException("artifact signature does not verify");
    }
    return new VerifiedArtifact(
        mapper.readTree(parsed.getHeader().toString()),
        mapper.readTree(parsed.getPayload().toString()));
  }

  /**
   * Activates a snapshot authorizing the synthetic issuer unless the current
   * one already does, and returns the governing version. Tests share one
   * container, so no test may assume which version is current.
   */
  public static long ensureSyntheticIssuer(JdbcTemplate owner, TrustService trust,
      ObjectMapper mapper) throws Exception {
    var current = trust.currentSnapshot();
    if (current.isPresent() && authorizesSynth(current.get(), Instant.now())) {
      return current.get().version();
    }
    Map<String, Object> genesis =
        owner.queryForMap(
            "SELECT issuer_id, display_name, scope, credential_types, key_id, public_key_jwk"
                + " FROM issuer_record WHERE snapshot_version ="
                + " (SELECT MIN(snapshot_version) FROM trust_snapshot_activation)"
                + " AND issuer_id = ?",
            ISSUER_ID);
    TestAccount maker = TestAccounts.create(owner, "synth-maker", Set.of("TRUST_ADMIN"));
    TestAccount checker = TestAccounts.create(owner, "synth-checker", Set.of("TRUST_ADMIN"));
    Instant now = Instant.now();
    var input =
        new TrustService.ProposalInput(
            List.of(
                new TrustService.IssuerInput(
                    (String) genesis.get("issuer_id"),
                    (String) genesis.get("display_name"),
                    (String) genesis.get("scope"),
                    List.of((String[]) ((java.sql.Array) genesis.get("credential_types"))
                        .getArray()),
                    (String) genesis.get("key_id"),
                    1,
                    mapper.readTree(String.valueOf(genesis.get("public_key_jwk"))),
                    now.minusSeconds(60),
                    now.plus(java.time.Duration.ofDays(3650)),
                    "ACTIVE")),
            List.of());
    TrustService.ProposalResult result =
        asCall(maker, () -> trust.propose(asPrincipal(maker), input, "test: restore synthetic issuer"));
    asRun(checker, () -> trust.approve(asPrincipal(checker), result.proposalId()));
    asRun(checker, () -> trust.activate(asPrincipal(checker), result.version()));
    return result.version();
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

  public static boolean authorizesSynth(TrustService.SnapshotView snapshot, Instant now) {
    return snapshot.issuers().stream()
        .anyMatch(
            issuer ->
                ISSUER_ID.equals(issuer.issuerId())
                    && "ACTIVE".equals(issuer.status())
                    && !issuer.validFrom().isAfter(now)
                    && !issuer.validThrough().isBefore(now)
                    && issuer.credentialTypes().contains(ADULT_VCT));
  }

  public static ServiceAccountPrincipal asPrincipal(TestAccount account) {
    return new ServiceAccountPrincipal(
        account.accountId(), account.tenantId(), account.name(), account.roles());
  }
}
