package dev.sovra.verification;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import dev.sovra.crypto.HolderProofException;
import dev.sovra.crypto.HolderProofs;
import dev.sovra.issuance.WaltIdSdJwtVcEncoder;
import dev.sovra.trust.TrustService;
import id.walt.sdjwt.JWTCryptoProvider;
import id.walt.sdjwt.JwtVerificationResult;
import id.walt.sdjwt.SDJwt;
import id.walt.sdjwt.VerificationResult;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.UUID;
import kotlinx.serialization.json.JsonElement;
import kotlinx.serialization.json.JsonObject;
import kotlinx.serialization.json.JsonElementKt;
import kotlinx.serialization.json.JsonPrimitive;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * SD-JWT VC verification path over the qualified walt-id module
 * (SOV-036). Checks a stored {@code dc+sd-jwt} artifact against the
 * live trust snapshot: container shape, issuer scope and epoch,
 * authorized key, walt-id signature plus disclosure integrity, and
 * claim bindings including {@code cnf} holder binding. Holder
 * proof-of-possession stays at the Sovra protocol layer (binding
 * proof), unchanged from the synthetic path. Every failure carries a
 * safe reason code; callers turn it into a REJECTED decision, never
 * an acceptance. Walt-id parse errors embed the artifact, so their
 * messages are never propagated.
 */
public final class WaltIdArtifactVerifier {

  private WaltIdArtifactVerifier() {}

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

  public static void verify(
      String artifact,
      Expected expected,
      TrustService.SnapshotView snapshot,
      JdbcTemplate tenant,
      ObjectMapper mapper,
      Instant now) {
    SDJwt parsed = parse(artifact);
    JsonObject header = header(parsed);
    if (!"ES256".equals(text(header, "alg"))
        || !WaltIdSdJwtVcEncoder.TYP.equals(text(header, "typ"))
        || text(header, "kid") == null) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    TrustService.IssuerView issuer = authorizedIssuer(snapshot, expected, now);
    if (!issuer.keyId().equals(text(header, "kid"))
        || !dev.sovra.trust.IssuerKeys.active(
            tenant, expected.issuerId(), issuer.keyId(), issuer.keyVersion())) {
      throw new ArtifactFailure("ISSUER_KEY_INACTIVE");
    }
    ECPublicKey issuerKey = issuerKey(issuer.publicKeyJwk());
    VerificationResult<SDJwt> result;
    try {
      result = parsed.verify(new VerifyOnlyProvider(issuerKey), text(header, "kid"));
    } catch (RuntimeException e) {
      throw new ArtifactFailure("ARTIFACT_SIGNATURE_INVALID");
    }
    if (!result.getSignatureVerified()) {
      throw new ArtifactFailure("ARTIFACT_SIGNATURE_INVALID");
    }
    if (!result.getDisclosuresVerified()) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    JsonObject claims;
    try {
      claims = parsed.getSdPayload().getFullPayload();
    } catch (RuntimeException e) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    if (!expected.issuerId().equals(text(claims, "iss"))
        || !expected.credentialId().toString().equals(text(claims, "jti"))
        || !expected.vct().equals(text(claims, "vct"))) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    if (!longEquals(claims, "exp", expected.expiresAt().getEpochSecond())) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    if (!expected.holderThumbprint().equals(cnfThumbprint(claims))) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    JsonElement disclosed = claims.get("claims");
    JsonElement adult =
        disclosed instanceof JsonObject object ? object.get("adultOver18") : null;
    if (!(disclosed instanceof JsonObject object)
        || object.size() != 1
        || !(adult instanceof JsonPrimitive primitive)
        || JsonElementKt.getBooleanOrNull(primitive) == null
        || !JsonElementKt.getBoolean(primitive)) {
      throw new ArtifactFailure("CLAIMS_MISMATCH");
    }
  }

  private static SDJwt parse(String artifact) {
    if (artifact == null || artifact.isBlank()) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
    try {
      return SDJwt.Companion.parse(artifact);
    } catch (RuntimeException e) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
    }
  }

  private static JsonObject header(SDJwt parsed) {
    try {
      return parsed.getHeader();
    } catch (RuntimeException e) {
      throw new ArtifactFailure("ARTIFACT_INVALID");
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
        || !dev.sovra.issuance.SyntheticJwtEncoder.ADULT_VCT.equals(expected.vct())) {
      throw new ArtifactFailure("TYPE_OUT_OF_SCOPE");
    }
    return issuer;
  }

  private static ECPublicKey issuerKey(JsonNode jwk) {
    try {
      return HolderProofs.parseP256Key(jwk);
    } catch (HolderProofException e) {
      throw new ArtifactFailure("ISSUER_KEY_INACTIVE");
    }
  }

  private static String text(JsonObject object, String field) {
    JsonElement child = object == null ? null : object.get(field);
    if (child instanceof JsonPrimitive primitive && primitive.isString()) {
      return primitive.getContent();
    }
    return null;
  }

  private static boolean longEquals(JsonObject object, String field, long expected) {
    JsonElement child = object == null ? null : object.get(field);
    if (!(child instanceof JsonPrimitive primitive)) {
      return false;
    }
    try {
      return JsonElementKt.getLong(primitive) == expected;
    } catch (RuntimeException e) {
      return false;
    }
  }

  private static String cnfThumbprint(JsonObject claims) {
    try {
      JsonElement cnf = claims.get("cnf");
      JsonElement jwk = cnf instanceof JsonObject object ? object.get("jwk") : null;
      if (!(jwk instanceof JsonObject key)) {
        return null;
      }
      String x = text(key, "x");
      String y = text(key, "y");
      if (x == null
          || y == null
          || !"EC".equals(text(key, "kty"))
          || !"P-256".equals(text(key, "crv"))) {
        return null;
      }
      byte[] rawX = com.nimbusds.jose.util.Base64URL.from(x).decode();
      byte[] rawY = com.nimbusds.jose.util.Base64URL.from(y).decode();
      if (rawX.length != 32 || rawY.length != 32) {
        return null;
      }
      return dev.sovra.issuance.LocalDevSigner.thumbprint(
          new BigInteger(1, rawX), new BigInteger(1, rawY));
    } catch (RuntimeException e) {
      return null;
    }
  }

  /** Verification-only crypto provider: signs nothing, verifies with one key. */
  private static final class VerifyOnlyProvider implements JWTCryptoProvider {
    private final ECPublicKey key;

    VerifyOnlyProvider(ECPublicKey key) {
      this.key = key;
    }

    @Override
    public String sign(
        kotlinx.serialization.json.JsonObject payload,
        String keyID,
        String typ,
        java.util.Map<String, ?> headers) {
      throw new UnsupportedOperationException("verification-only provider");
    }

    @Override
    public JwtVerificationResult verify(String jwt, String keyID) {
      try {
        boolean ok =
            com.nimbusds.jwt.SignedJWT.parse(jwt).verify(new ECDSAVerifier(key));
        return new JwtVerificationResult(ok, "");
      } catch (Exception e) {
        return new JwtVerificationResult(false, "");
      }
    }
  }
}
