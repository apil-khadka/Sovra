package dev.sovra.sdk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/** Issuer/RP quickstart (SOV-021): issue, consent, present, verify. */
class SdkIssuanceFlowTest extends SdkLiveBase {

  static final String RP_ID = "https://rp.example/synth-shop";
  static final String AUDIENCE = "https://rp.example/synth-shop/callback";
  static final String PURPOSE = "synthetic age check at checkout";
  static final String POLICY_ID = "sovra-synthetic-policy/age-check";
  static final String POLICY_VERSION = "1";
  static final String SECTION_ID = "age_eligibility";

  @Test
  void issueConsentVerifyQuickstart() throws Exception {
    MachineAccount issuer = mintAccount("sdk-issuer", "ISSUER_OPS");
    MachineAccount rp = mintAccount("sdk-rp", "RP_CLIENT,TENANT_MEMBER");
    ObjectMapper mapper = new ObjectMapper();
    TestHolders.HolderKeys holder = TestHolders.generate(mapper);
    String thumbprint = TestHolders.thumbprint(holder);
    String key = Idempotency.mint();
    String expires = Instant.now().plusSeconds(7200).toString();
    try (SovraClient issuerClient = clientFor(issuer.token());
        SovraClient rpClient = clientFor(rp.token())) {
      // Issue.
      IssuanceClient.IssuedCredential issued = issuerClient.issuance.issue(
          key, ISSUER_ID, ADULT_VCT, holder.jwk(),
          TestHolders.proofOver(holder,
              "sovra-issuance-proof/v1\n" + key + "\n" + ADULT_VCT + "\n" + thumbprint
                  + "\nadultOver18=true"),
          Map.of("adultOver18", Boolean.TRUE), expires, null);
      assertThat(issued.status()).isEqualTo("VALID");
      assertThat(issuerClient.issuance.status(issued.credentialId()).status())
          .isEqualTo("VALID");
      assertThat(issuerClient.issuance.get(issued.credentialId()).credentialId())
          .isEqualTo(issued.credentialId());

      // Consent: RP opens, holder approves.
      String planId = "pln_sdk_" + randomHex(12);
      ConsentClient.RequestView created = rpClient.consent.create(
          RP_ID, AUDIENCE, PURPOSE, issued.credentialId(),
          Map.of("adultOver18", Boolean.TRUE), planWire(planId), POLICY_ID, POLICY_VERSION,
          planHash(planId), randomBase64Url(24), Instant.now().plusSeconds(3600).toString());
      assertThat(created.state()).isEqualTo("PENDING");
      ConsentClient.RequestView review = rpClient.consent.review(created.requestId());
      String consentMessage = "sovra-consent/v1\n" + review.requestId() + "\napprove\n"
          + review.rpId() + "\n" + review.audience() + "\n" + review.purpose() + "\n"
          + "adultOver18=true\n" + review.planHash() + "\n" + review.challenge() + "\n"
          + review.expiresAt() + "\n" + review.holderThumbprint();
      ConsentClient.RequestView decided = rpClient.consent.decide(
          created.requestId(), "approve", holder.jwk(),
          TestHolders.proofOver(holder, consentMessage));
      assertThat(decided.state()).isEqualTo("VERIFIED");
      ConsentClient.PresentationView presentation =
          rpClient.consent.presentation(created.requestId());
      assertThat(presentation.presentation().split("\\.")).hasSize(3);

      // Verify.
      String nonce = Idempotency.mint();
      String bindingProof = TestHolders.proofOver(holder,
          "sovra-presentation/v1\n" + created.requestId() + "\n" + nonce + "\n" + AUDIENCE
              + "\n" + thumbprint);
      VerificationClient.Decision decision = rpClient.verification.verify(
          created.requestId(), nonce, AUDIENCE, holder.jwk(), bindingProof);
      assertThat(decision.outcome()).isEqualTo("ACCEPTED");
      // Identical bytes replay the stored decision.
      VerificationClient.Decision replay = rpClient.verification.verify(
          created.requestId(), nonce, AUDIENCE, holder.jwk(), bindingProof);
      assertThat(replay.decisionId()).isEqualTo(decision.decisionId());
      assertThat(rpClient.verification.get(decision.decisionId()).outcome())
          .isEqualTo("ACCEPTED");
    }
  }

  @Test
  void issuanceRejectsUnreviewedClaims() throws Exception {
    MachineAccount issuer = mintAccount("sdk-neg", "ISSUER_OPS");
    ObjectMapper mapper = new ObjectMapper();
    TestHolders.HolderKeys holder = TestHolders.generate(mapper);
    String key = Idempotency.mint();
    try (SovraClient client = clientFor(issuer.token())) {
      assertThatThrownBy(() -> client.issuance.issue(
          key, ISSUER_ID, ADULT_VCT, holder.jwk(),
          TestHolders.proofOver(holder,
              "sovra-issuance-proof/v1\n" + key + "\n" + ADULT_VCT + "\n"
                  + TestHolders.thumbprint(holder) + "\nadultOver18=true"),
          Map.of("adultOver18", Boolean.TRUE, "smuggled", "x"),
          Instant.now().plusSeconds(3600).toString(), null))
          .isInstanceOf(SovraApiError.class)
          .satisfies(e -> assertThat(((SovraApiError) e).status()).isEqualTo(400));
    }
  }

  static Map<String, Object> planWire(String planId) {
    return Map.of(
        "plan_id", planId,
        "requested_outcome", "age_over_18",
        "candidate_issuer_id", ISSUER_ID,
        "credential_type", ADULT_VCT,
        "claim_paths", List.of("adultOver18"),
        "evidence", List.of(Map.of("document_id", POLICY_ID, "section_id", SECTION_ID)),
        "policy_id", POLICY_ID,
        "policy_version", POLICY_VERSION,
        "recommendation", "CANDIDATE_ONLY");
  }

  static String planHash(String planId) throws Exception {
    String canonical = String.join("\n",
        "sovra-plan/v1", planId, "age_over_18", ISSUER_ID, ADULT_VCT, "adultOver18",
        POLICY_ID + "#" + SECTION_ID, POLICY_ID, POLICY_VERSION, "CANDIDATE_ONLY", "");
    return HexFormat.of().formatHex(
        MessageDigest.getInstance("SHA-256")
            .digest(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  }

  static String randomHex(int bytes) {
    byte[] random = new byte[bytes];
    new SecureRandom().nextBytes(random);
    return HexFormat.of().formatHex(random);
  }

  static String randomBase64Url(int bytes) {
    byte[] random = new byte[bytes];
    new SecureRandom().nextBytes(random);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(random);
  }
}
