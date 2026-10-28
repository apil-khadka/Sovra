package dev.sovra.verification;

import com.nimbusds.jose.util.Base64URL;
import dev.sovra.crypto.HolderProofException;
import dev.sovra.crypto.HolderProofs;
import dev.sovra.issuance.SyntheticJwtEncoder;
import dev.sovra.trust.TrustService;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Synthetic-credential verification path (SOV-011). Checks the stored
 * G1 artifact — deliberately NOT an SD-JWT VC — against the live trust
 * snapshot: content type, issuer scope and epoch, authorized key, ES256
 * signature, and claim bindings. Every failure carries a safe reason
 * code; callers turn it into a REJECTED decision, never an acceptance.
 *
 * <p>The interoperable SD-JWT VC/OpenID4VP gate stays closed until
 * SOV-036 qualifies a profile; this path only ever verifies content
 * labelled synthetic.
 */
public final class SyntheticArtifactVerifier {

  private SyntheticArtifactVerifier() {}

  public record Expected(
      String issuerId, String vct, String holderThumbprint, UUID credentialId, Instant expiresAt) {}

  /** A failed artifact check with its safe decision reason code. */
  public static class ArtifactFailure extends RuntimeException {
    private final String reason;

    ArtifactFailure(String reason) {
      super(reason);
      this.reason = reason;
    }

    public String reason() {
      return reason;
    }
  }

  /**
   * Verifies the stored artifact or throws {@link ArtifactFailure}.
   * Signature verification precedes claim checks, but every check fails
   * closed, so order only selects the reported reason.
   */
  public static void verify(
      String artifact,
      Expected expected,
      TrustService.SnapshotView snapshot,
      JdbcTemplate tenant,
      ObjectMapper mapper,
      Instant now) {
    JsonNode header = header(artifact, mapper);
    if (!"ES256".equals(text(header, "alg"))
        || !SyntheticJwtEncoder.CONTENT_TYPE.equals(text(header, "typ"))
        || text(header, "kid") == null) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    TrustService.IssuerView issuer = authorizedIssuer(snapshot, expected, now);
    if (!issuer.keyId().equals(text(header, "kid")) || !signingKeyActive(tenant, expected, issuer)) {
      throw new ArtifactFailure("ISSUER_KEY_INACTIVE");
    }
    ECPublicKey issuerKey = issuerKey(issuer.publicKeyJwk());
    String[] parts = signature(issuerKey, artifact);
    JsonNode claims = claims(parts[1], mapper);
    JsonNode synthetic = claims.get("synthetic");
    if (synthetic == null || !synthetic.isBoolean() || !synthetic.asBoolean()
        || !VerificationService.PROFILE.equals(text(claims, "profile"))) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    if (!expected.issuerId().equals(text(claims, "iss"))
        || !expected.credentialId().toString().equals(text(claims, "jti"))
        || !expected.holderThumbprint().equals(text(claims, "sub"))
        || !expected.vct().equals(text(claims, "vct"))) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    JsonNode exp = claims.get("exp");
    if (exp == null || !exp.isNumber() || exp.asLong() != expected.expiresAt().getEpochSecond()) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    JsonNode disclosed = claims.get("claims");
    JsonNode adult = disclosed == null ? null : disclosed.get("adultOver18");
    if (disclosed == null
        || disclosed.size() != 1
        || adult == null
        || !adult.isBoolean()
        || !adult.asBoolean()) {
      throw new ArtifactFailure("CLAIMS_MISMATCH");
    }
  }

  private static TrustService.IssuerView authorizedIssuer(
      TrustService.SnapshotView snapshot, Expected expected, Instant now) {
    TrustService.IssuerView issuer =
        snapshot.issuers().stream()
            .filter(i -> expected.issuerId().equals(i.issuerId()))
            .findFirst()
            .orElseThrow(() -> new ArtifactFailure("ISSUER_UNTRUSTED"));
    if (!"ACTIVE".equals(issuer.status())
        || issuer.validFrom().isAfter(now)
        || issuer.validThrough().isBefore(now)) {
      throw new ArtifactFailure("ISSUER_UNTRUSTED");
    }
    if (!issuer.credentialTypes().contains(expected.vct())
        || !SyntheticJwtEncoder.ADULT_VCT.equals(expected.vct())) {
      throw new ArtifactFailure("TYPE_OUT_OF_SCOPE");
    }
    return issuer;
  }

  private static boolean signingKeyActive(
      JdbcTemplate tenant, Expected expected, TrustService.IssuerView issuer) {
    return dev.sovra.trust.IssuerKeys.active(
        tenant, expected.issuerId(), issuer.keyId(), issuer.keyVersion());
  }

  private static ECPublicKey issuerKey(JsonNode jwk) {
    try {
      return HolderProofs.parseP256Key(jwk);
    } catch (HolderProofException e) {
      throw new ArtifactFailure("ISSUER_KEY_INACTIVE");
    }
  }

  private static String[] signature(ECPublicKey issuerKey, String artifact) {
    if (artifact == null || artifact.isBlank()) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    try {
      return HolderProofs.verifySignature(issuerKey, artifact);
    } catch (HolderProofException e) {
      if ("signature container is malformed".equals(e.getMessage())) {
        throw new ArtifactFailure("ARTIFACT_INVALID");
      }
      throw new ArtifactFailure("ARTIFACT_SIGNATURE_INVALID");
    }
  }

  private static JsonNode header(String artifact, ObjectMapper mapper) {
    String[] parts = artifact == null ? new String[0] : artifact.split("\\.", -1);
    if (parts.length != 3) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    try {
      return mapper.readTree(Base64URL.from(parts[0]).decode());
    } catch (JacksonException | IllegalArgumentException e) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
  }

  private static JsonNode claims(String payload, ObjectMapper mapper) {
    try {
      return mapper.readTree(
          new String(Base64URL.from(payload).decode(), StandardCharsets.UTF_8));
    } catch (JacksonException | IllegalArgumentException e) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
  }

  private static String text(JsonNode node, String field) {
    JsonNode child = node == null ? null : node.get(field);
    return child != null && child.isString() ? child.asString() : null;
  }
}
