package dev.sovra.consent;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.issuance.IssuanceFixtures;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/** Proof-request bodies and holder consent proofs for consent tests. */
public final class ConsentFixtures {

  public static final String RP_ID = "https://rp.example/synth-shop";
  public static final String AUDIENCE = "https://rp.example/synth-shop/callback";
  public static final String PURPOSE = "synthetic age check at checkout";

  private ConsentFixtures() {}

  public static String planHash() {
    byte[] raw = new byte[32];
    new SecureRandom().nextBytes(raw);
    return HexFormat.of().formatHex(raw);
  }

  public static String challenge() {
    byte[] raw = new byte[24];
    new SecureRandom().nextBytes(raw);
    return Base64URL.encode(raw).toString();
  }

  public static Map<String, Object> createBody(UUID credentialId) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("rpId", RP_ID);
    body.put("audience", AUDIENCE);
    body.put("purpose", PURPOSE);
    body.put("credentialId", credentialId.toString());
    body.put("claims", Map.of("adultOver18", Boolean.TRUE));
    body.put("planHash", planHash());
    body.put("challenge", challenge());
    body.put("expiresAt", Instant.now().plusSeconds(3600).toString());
    return body;
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> create(
      RestClient client, TestAccount rp, Map<String, Object> body) {
    return client
        .post()
        .uri("/api/consent/requests")
        .headers(rp.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(Map.class);
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> review(RestClient client, TestAccount viewer, String requestId) {
    return client
        .get()
        .uri("/api/consent/requests/" + requestId)
        .headers(viewer.headers())
        .retrieve()
        .body(Map.class);
  }

  /** Canonical consent message, mirroring ConsentService.consentMessage. */
  public static String consentMessage(Map<String, Object> review, String decision) {
    return ConsentService.CONSENT_LABEL + "\n" + review.get("requestId") + "\n" + decision + "\n"
        + review.get("rpId") + "\n" + review.get("audience") + "\n" + review.get("purpose") + "\n"
        + ConsentService.CLAIMS_CANONICAL + "\n" + review.get("planHash") + "\n"
        + review.get("challenge") + "\n" + review.get("expiresAt") + "\n"
        + review.get("holderThumbprint");
  }

  /** Holder-signed approve/deny proof over the reviewed request bytes. */
  public static String consentProof(
      IssuanceFixtures.HolderKeys holder,
      Map<String, Object> review,
      String decision,
      ObjectMapper mapper) throws Exception {
    return IssuanceFixtures.proofOver(holder, consentMessage(review, decision), mapper);
  }

  public static Map<String, Object> decideBody(
      IssuanceFixtures.HolderKeys holder,
      Map<String, Object> review,
      String decision,
      ObjectMapper mapper) throws Exception {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("decision", decision);
    body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
    body.put("consentProof", consentProof(holder, review, decision, mapper));
    return body;
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> decide(
      RestClient client, TestAccount holder, String requestId, Map<String, Object> body) {
    return client
        .post()
        .uri("/api/consent/requests/" + requestId + "/decision")
        .headers(holder.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(Map.class);
  }

  /** Issues a credential for the holder over HTTP; returns the credential id. */
  @SuppressWarnings("unchecked")
  public static String issueCredential(
      RestClient client,
      TestAccount issuer,
      IssuanceFixtures.HolderKeys holder,
      ObjectMapper mapper) throws Exception {
    String key = "consent-" + UUID.randomUUID();
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("issuerId", IssuanceFixtures.ISSUER_ID);
    body.put("vct", IssuanceFixtures.ADULT_VCT);
    body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
    body.put("holderProof",
        IssuanceFixtures.proof(holder, key, IssuanceFixtures.ADULT_VCT, mapper));
    body.put("claims", Map.of("adultOver18", Boolean.TRUE));
    body.put("expiresAt", Instant.now().plusSeconds(7200).toString());
    Map<String, Object> response =
        client
            .post()
            .uri("/api/issuance/credentials")
            .headers(
                h -> {
                  issuer.headers().accept(h);
                  h.set("Idempotency-Key", key);
                })
            .contentType(MediaType.APPLICATION_JSON)
            .body(body)
            .retrieve()
            .body(Map.class);
    assert response != null;
    return response.get("credentialId").toString();
  }

  public record VerifiedPresentation(String payload) {}

  /** Verifies the presentation JWS against the holder key (Nimbus path). */
  public static VerifiedPresentation verifyPresentation(
      String presentation, IssuanceFixtures.HolderKeys holder) throws Exception {
    ECKey key =
        new ECKey.Builder(
                Curve.P_256,
                Base64URL.from(IssuanceFixtures.base64UrlUnsigned(
                    holder.publicKey().getW().getAffineX())),
                Base64URL.from(IssuanceFixtures.base64UrlUnsigned(
                    holder.publicKey().getW().getAffineY())))
            .build();
    JWSObject parsed = JWSObject.parse(presentation);
    if (!parsed.verify(new ECDSAVerifier(key))) {
      throw new IllegalStateException("presentation signature does not verify");
    }
    return new VerifiedPresentation(
        new String(parsed.getPayload().toBytes(), StandardCharsets.UTF_8));
  }
}
