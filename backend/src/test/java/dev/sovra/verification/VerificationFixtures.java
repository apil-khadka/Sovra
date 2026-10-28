package dev.sovra.verification;

import com.nimbusds.jose.util.Base64URL;
import dev.sovra.TestAccounts;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/** Verification submissions, holder binding proofs, and approved stages. */
public final class VerificationFixtures {

  private VerificationFixtures() {}

  public record Stage(
      TestAccount issuer, TestAccount rp, TestAccount holderAgent,
      IssuanceFixtures.HolderKeys holder, String credentialId, String requestId,
      Map<String, Object> review) {}

  /** Fresh verifier nonce, same shape as the consent challenge. */
  public static String nonce() {
    byte[] raw = new byte[24];
    new SecureRandom().nextBytes(raw);
    return Base64URL.encode(raw).toString();
  }

  /** Canonical presentation message, mirroring VerificationService. */
  public static String presentationMessage(
      String requestId, String nonce, String audience, String holderThumbprint) {
    return VerificationService.PRESENTATION_LABEL + "\n" + requestId + "\n" + nonce + "\n"
        + audience + "\n" + holderThumbprint;
  }

  /** Holder-signed binding proof over this verification attempt. */
  public static String bindingProof(
      IssuanceFixtures.HolderKeys holder,
      String requestId,
      String nonce,
      String audience,
      ObjectMapper mapper) throws Exception {
    return IssuanceFixtures.proofOver(
        holder,
        presentationMessage(requestId, nonce, audience, IssuanceFixtures.thumbprint(holder)),
        mapper);
  }

  public static Map<String, Object> verifyBody(
      IssuanceFixtures.HolderKeys holder,
      String requestId,
      String nonce,
      String audience,
      ObjectMapper mapper) throws Exception {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("requestId", requestId);
    body.put("nonce", nonce);
    body.put("audience", audience);
    body.put("holderJwk", mapper.convertValue(holder.jwk(), Map.class));
    body.put("bindingProof", bindingProof(holder, requestId, nonce, audience, mapper));
    return body;
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> verify(
      RestClient client, TestAccount rp, Map<String, Object> body) {
    return client
        .post()
        .uri("/api/verification/presentations")
        .headers(rp.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(Map.class);
  }

  /** Raw response bytes for byte-identical replay assertions. */
  public static String verifyRaw(RestClient client, TestAccount rp, Map<String, Object> body) {
    return client
        .post()
        .uri("/api/verification/presentations")
        .headers(rp.headers())
        .contentType(MediaType.APPLICATION_JSON)
        .body(body)
        .retrieve()
        .body(String.class);
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> decision(
      RestClient client, TestAccount viewer, String decisionId) {
    return client
        .get()
        .uri("/api/verification/decisions/" + decisionId)
        .headers(viewer.headers())
        .retrieve()
        .body(Map.class);
  }

  /**
   * Full approved stage: issued credential, created proof request, and
   * holder-signed approval. Returns everything a submission needs.
   */
  public static Stage approvedStage(
      RestClient client, JdbcTemplate owner, ObjectMapper mapper, String tag) throws Exception {
    TestAccount issuer = TestAccounts.create(owner, tag + "-issuer", Set.of("ISSUER_OPS"));
    TestAccount rp = TestAccounts.createInTenant(
        owner, issuer.tenantId(), tag + "-rp", Set.of("RP_CLIENT"));
    TestAccount holderAgent = TestAccounts.createInTenant(
        owner, issuer.tenantId(), tag + "-agent", Set.of("TENANT_MEMBER"));
    IssuanceFixtures.HolderKeys holder = IssuanceFixtures.generateHolder(mapper);
    String credentialId = ConsentFixtures.issueCredential(client, issuer, holder, mapper);
    Map<String, Object> created = ConsentFixtures.create(
        client, rp, ConsentFixtures.createBody(UUID.fromString(credentialId)));
    assert created != null;
    String requestId = created.get("requestId").toString();
    Map<String, Object> review = ConsentFixtures.review(client, rp, requestId);
    ConsentFixtures.decide(client, holderAgent, requestId,
        ConsentFixtures.decideBody(holder, review, "approve", mapper));
    Map<String, Object> reread = ConsentFixtures.review(client, rp, requestId);
    return new Stage(issuer, rp, holderAgent, holder, credentialId, requestId, reread);
  }
}
