package dev.sovra.issuance;

import id.walt.sdjwt.JWTCryptoProvider;
import id.walt.sdjwt.JwtVerificationResult;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import kotlinx.serialization.json.JsonObject;

/**
 * walt-id signing bridge backed by Sovra's constrained signer (SOV-036).
 * The only signing path the SD-JWT VC encoder may use: every call
 * re-authorizes the key through {@link IssuerSigner}, refuses unexpected
 * key IDs and headers, and records the call context. Verification is
 * deliberately unsupported here — verification uses
 * {@code WaltIdArtifactVerifier} with trust-snapshot keys.
 */
public final class SovraIssuerCryptoProvider implements JWTCryptoProvider {

  private final IssuerSigner signer;
  private final KeyRef keyRef;
  private final UUID credentialId;

  public SovraIssuerCryptoProvider(IssuerSigner signer, KeyRef keyRef, UUID credentialId) {
    this.signer = signer;
    this.keyRef = keyRef;
    this.credentialId = credentialId;
  }

  @Override
  public String sign(JsonObject payload, String keyID, String typ, Map<String, ?> headers) {
    if (!keyRef.keyId().equals(keyID)) {
      throw new IllegalStateException("signing call names an unexpected key");
    }
    if (headers != null && !headers.isEmpty()) {
      throw new IllegalStateException("unexpected protected headers in signing call");
    }
    if (payload == null || typ == null || typ.isBlank()) {
      throw new IllegalStateException("signing call is incomplete");
    }
    String headerJson =
        "{\"alg\":\"ES256\",\"typ\":\"" + typ + "\",\"kid\":\"" + keyID + "\"}";
    String signingInput =
        base64Url(headerJson) + "." + base64Url(payload.toString());
    String aad =
        AadContext.issuance(
                keyRef.issuerId(), keyRef.encode(), credentialId.toString(),
                WaltIdSdJwtVcEncoder.PROFILE)
            .encode();
    byte[] signature =
        signer.sign(keyRef, signingInput.getBytes(StandardCharsets.US_ASCII), aad);
    return signingInput + "." + base64Url(signature);
  }

  @Override
  public JwtVerificationResult verify(String jwt, String keyID) {
    throw new UnsupportedOperationException(
        "issuance-only provider; verification uses WaltIdArtifactVerifier");
  }

  private static String base64Url(String text) {
    return base64Url(text.getBytes(StandardCharsets.UTF_8));
  }

  private static String base64Url(byte[] raw) {
    return com.nimbusds.jose.util.Base64URL.encode(raw).toString();
  }
}
