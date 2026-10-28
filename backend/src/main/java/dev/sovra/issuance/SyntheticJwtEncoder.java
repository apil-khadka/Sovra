package dev.sovra.issuance;

import com.nimbusds.jose.util.Base64URL;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

/**
 * G1 synthetic credential encoder. Emits a compact ES256 JWS that is
 * deliberately NOT an SD-JWT VC: {@code typ} names it synthetic, the
 * body carries {@code synthetic: true} plus the profile label, and only
 * the SOV-001 claim allowlist ({@code adultOver18: true}) survives.
 * Verifiers must reject this content type outside synthetic use.
 */
@Service
@ConditionalOnProperty(name = "sovra.profile", havingValue = "synthetic", matchIfMissing = true)
public class SyntheticJwtEncoder implements CredentialEncoder {

  public static final String CONTENT_TYPE = "vnd.sovra.synthetic-credential+jwt";
  public static final String PROFILE = "sovra-g1-synthetic/0.2";
  public static final String ADULT_VCT = "https://sovra.example/vct/adult-status/1";

  private final IssuerSigner signer;
  private final ObjectMapper mapper;

  public SyntheticJwtEncoder(IssuerSigner signer, ObjectMapper mapper) {
    this.signer = signer;
    this.mapper = mapper;
  }

  @Override
  public EncodedCredential encode(IssuanceEvidence evidence) {
    allowlistClaims(evidence.vct(), evidence.claims());
    try {
      Map<String, Object> header = Map.of("alg", "ES256", "typ", CONTENT_TYPE, "kid",
          evidence.keyRef().keyId());
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("iss", evidence.issuerId());
      body.put("sub", evidence.holderThumbprint());
      body.put("jti", evidence.credentialId().toString());
      body.put("iat", evidence.issuedAt().getEpochSecond());
      body.put("exp", evidence.expiresAt().getEpochSecond());
      body.put("vct", evidence.vct());
      body.put("claims", evidence.claims());
      body.put("status_uri", evidence.statusUri());
      body.put("trust_snapshot", evidence.trustSnapshotVersion());
      body.put("synthetic", true);
      body.put("profile", PROFILE);
      String claimsJson = mapper.writeValueAsString(body);
      String signingInput =
          base64Url(mapper.writeValueAsString(header)) + "." + base64Url(claimsJson);
      // AAD context mirrors the evidence; the signer refuses unless it
      // names this call's issuer (see IssuerSigner).
      String aad =
          "issuer=" + evidence.issuerId()
              + ";key=" + evidence.keyRef().encode()
              + ";credential=" + evidence.credentialId()
              + ";purpose=issuance;schema=" + PROFILE;
      byte[] signature =
          signer.sign(evidence.keyRef(), signingInput.getBytes(StandardCharsets.US_ASCII), aad);
      String artifact = signingInput + "." + Base64URL.encode(signature);
      return new EncodedCredential(artifact, claimsJson);
    } catch (JacksonException e) {
      throw new IllegalStateException("evidence is not JSON-encodable", e);
    }
  }

  /** Defense in depth: the allowlist holds even if a caller skips checks. */
  static void allowlistClaims(String vct, Map<String, Object> claims) {
    if (!ADULT_VCT.equals(vct)) {
      throw new InvalidIssuanceException("credential type is not permitted");
    }
    if (claims == null || claims.size() != 1 || !Boolean.TRUE.equals(claims.get("adultOver18"))) {
      throw new InvalidIssuanceException("claims are not permitted for this type");
    }
  }

  private static String base64Url(String text) {
    return Base64URL.encode(text.getBytes(StandardCharsets.UTF_8)).toString();
  }
}
