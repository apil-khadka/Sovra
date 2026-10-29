package dev.sovra.issuance;

import dev.sovra.crypto.HolderProofException;
import dev.sovra.crypto.HolderProofs;
import id.walt.sdjwt.SDJwt;
import id.walt.sdjwt.SDMap;
import id.walt.sdjwt.SDMapBuilder;
import id.walt.sdjwt.SDPayload;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlinx.serialization.json.JsonElement;
import kotlinx.serialization.json.JsonObject;
import kotlinx.serialization.json.JsonElementKt;
import kotlinx.serialization.json.JsonPrimitive;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;

/**
 * SD-JWT VC encoder over the qualified walt-id module (SOV-036). Issues
 * a real {@code dc+sd-jwt} credential: registered claims plus a
 * selectively disclosable {@code claims} object, holder-bound via
 * {@code cnf.jwk}, signed through the constrained {@link IssuerSigner}.
 * Status stays out-of-band at {@code status_uri} (G1 synthetic status);
 * the Token Status List wire shape is a later profile step.
 *
 * <p>Selected with {@code sovra.profile=sdjwt-vc}; the default profile
 * remains the labelled synthetic JWT.
 */
@Service
@ConditionalOnProperty(name = "sovra.profile", havingValue = "sdjwt-vc")
public class WaltIdSdJwtVcEncoder implements CredentialEncoder {

  public static final String PROFILE = "sovra-sdjwt-vc/1.0";
  public static final String TYP = "dc+sd-jwt";

  private final IssuerSigner signer;

  public WaltIdSdJwtVcEncoder(IssuerSigner signer) {
    this.signer = signer;
  }

  @Override
  public EncodedCredential encode(IssuanceEvidence evidence) {
    SyntheticJwtEncoder.allowlistClaims(evidence.vct(), evidence.claims());
    if (evidence.holderJwk() == null) {
      throw new InvalidIssuanceException("holder key is required for SD-JWT VC binding");
    }
    JsonObject holderJwk = holderJwk(evidence.holderJwk());

    Map<String, JsonElement> full = new LinkedHashMap<>();
    full.put("iss", JsonElementKt.JsonPrimitive(evidence.issuerId()));
    full.put("sub", JsonElementKt.JsonPrimitive(evidence.holderThumbprint()));
    full.put("jti", JsonElementKt.JsonPrimitive(evidence.credentialId().toString()));
    full.put("iat", JsonElementKt.JsonPrimitive(evidence.issuedAt().getEpochSecond()));
    full.put("exp", JsonElementKt.JsonPrimitive(evidence.expiresAt().getEpochSecond()));
    full.put("vct", JsonElementKt.JsonPrimitive(evidence.vct()));
    full.put("cnf", new JsonObject(Map.of("jwk", holderJwk)));
    full.put("status_uri", JsonElementKt.JsonPrimitive(evidence.statusUri()));
    full.put(
        "claims",
        new JsonObject(Map.of("adultOver18", JsonElementKt.JsonPrimitive(Boolean.TRUE))));
    JsonObject payload = new JsonObject(full);

    SDMap disclosures =
        new SDMapBuilder()
            .addField(
                "claims",
                false,
                new SDMapBuilder().addField("adultOver18", true, null).build())
            .build();
    SDPayload sdPayload = SDPayload.Companion.createSDPayload(payload, disclosures);
    SDJwt sdJwt =
        SDJwt.Companion.sign(
            sdPayload,
            new SovraIssuerCryptoProvider(signer, evidence.keyRef(), evidence.credentialId()),
            evidence.keyRef().keyId(),
            TYP,
            Collections.emptyMap());
    return new EncodedCredential(sdJwt.toString());
  }

  private static JsonObject holderJwk(JsonNode jwk) {
    ECPublicKey key;
    try {
      key = HolderProofs.parseP256Key(jwk);
    } catch (HolderProofException e) {
      throw new InvalidIssuanceException("holder key is malformed");
    }
    return new JsonObject(
        Map.of(
            "kty", JsonElementKt.JsonPrimitive("EC"),
            "crv", JsonElementKt.JsonPrimitive("P-256"),
            "x",
            JsonElementKt.JsonPrimitive(
                dev.sovra.crypto.P256.base64UrlUnsigned(key.getW().getAffineX())),
            "y",
            JsonElementKt.JsonPrimitive(
                dev.sovra.crypto.P256.base64UrlUnsigned(key.getW().getAffineY()))));
  }

}
