package dev.sovra.openid;

import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.verification.VerificationFixtures;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Shared SOV-036 protocol fixtures: KeyBinding-bound verification
 * submissions for the {@code sdjwt-vc} profile, VCI wallet-drive
 * helpers, and VP session helpers. All holder artifacts come from
 * {@link NimbusWallet} (the independent wallet path).
 */
public final class OpenIdFixtures {

  private OpenIdFixtures() {}

  /** Stored artifact for KB {@code sd_hash} binding. */
  public static String storedArtifact(JdbcTemplate owner, String credentialId) {
    return owner.queryForObject(
        "SELECT artifact FROM credential_artifact WHERE id = ?", String.class,
        UUID.fromString(credentialId));
  }

  /** KeyBinding JWT over the stored artifact for this submission. */
  public static String kbProof(
      JdbcTemplate owner,
      IssuanceFixtures.HolderKeys holder,
      String credentialId,
      String nonce,
      String audience,
      ObjectMapper mapper)
      throws Exception {
    return NimbusWallet.keyBinding(
        holder, audience, nonce, storedArtifact(owner, credentialId), mapper);
  }

  /** Verification submission body with a KeyBinding proof (sdjwt-vc profile). */
  public static Map<String, Object> kbVerifyBody(
      JdbcTemplate owner,
      IssuanceFixtures.HolderKeys holder,
      String credentialId,
      String requestId,
      String nonce,
      String audience,
      ObjectMapper mapper)
      throws Exception {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("requestId", requestId);
    body.put("nonce", nonce);
    body.put("audience", audience);
    body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
    body.put("bindingProof", kbProof(owner, holder, credentialId, nonce, audience, mapper));
    return body;
  }

  // -- VCI wallet drive --------------------------------------------------

  @SuppressWarnings("unchecked")
  public static Map<String, Object> offer(
      RestClient client, TestAccount issuer, String issuerId, String vct) {
    return client
        .post()
        .uri("/api/vci/offers")
        .headers(issuer.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(Map.of("issuerId", issuerId, "vct", vct))
        .retrieve()
        .body(Map.class);
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> authorize(
      RestClient client, TestAccount holderAgent, String issuerId, String vct, String challenge) {
    return client
        .post()
        .uri("/api/vci/authorize")
        .headers(holderAgent.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(Map.of("issuerId", issuerId, "vct", vct, "codeChallenge", challenge))
        .retrieve()
        .body(Map.class);
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> tokenPreAuth(RestClient client, String code) {
    return client
        .post()
        .uri("/api/vci/token")
        .contentType(MediaType.APPLICATION_JSON)
        .body(
            Map.of(
                "grant_type", VciService.PRE_AUTH_GRANT,
                "pre-authorized_code", code))
        .retrieve()
        .body(Map.class);
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> tokenCode(
      RestClient client, String code, String verifier) {
    return client
        .post()
        .uri("/api/vci/token")
        .contentType(MediaType.APPLICATION_JSON)
        .body(
            Map.of(
                "grant_type", VciService.AUTH_CODE_GRANT,
                "code", code,
                "code_verifier", verifier))
        .retrieve()
        .body(Map.class);
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> credential(
      RestClient client, String accessToken, String configurationId, String proofJwt) {
    return client
        .post()
        .uri("/api/vci/credential")
        .header("Authorization", "Bearer " + accessToken)
        .contentType(MediaType.APPLICATION_JSON)
        .body(
            Map.of(
                "format", "dc+sd-jwt",
                "credential_configuration_id", configurationId,
                "proof", Map.of("proof_type", "jwt", "jwt", proofJwt)))
        .retrieve()
        .body(Map.class);
  }

  // -- VP wallet drive ---------------------------------------------------

  @SuppressWarnings("unchecked")
  public static Map<String, Object> vpRequest(
      RestClient client, TestAccount rp, String proofRequestId) {
    return client
        .post()
        .uri("/api/vp/requests")
        .headers(rp.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(Map.of("proofRequestId", proofRequestId))
        .retrieve()
        .body(Map.class);
  }

  public static String requestObject(RestClient client, String sessionId) {
    return client
        .get()
        .uri("/api/vp/requests/" + sessionId + "/object")
        .retrieve()
        .body(String.class);
  }

  public static String verifierJwks(RestClient client) {
    return client.get().uri("/api/vp/jwks.json").retrieve().body(String.class);
  }

  /** Encrypted {@code direct_post.jwt} submission (form-encoded, the spec shape). */
  @SuppressWarnings("unchecked")
  public static Map<String, Object> vpRespondForm(RestClient client, String sessionId, String jwe) {
    return client
        .post()
        .uri("/api/vp/responses/" + sessionId)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .body("response=" + urlEncode(jwe))
        .retrieve()
        .body(Map.class);
  }

  private static String urlEncode(String value) {
    return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
  }

  /** Consent fixtures audience, re-exported for protocol tests. */
  public static String audience() {
    return ConsentFixtures.AUDIENCE;
  }

  /** Fresh nonce, same shape as the verification challenge. */
  public static String nonce() {
    return VerificationFixtures.nonce();
  }
}
