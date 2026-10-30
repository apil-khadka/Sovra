package dev.sovra.sdk;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/** Enrollment + custody quickstart (SOV-021): case to approval, report, recover. */
class SdkEnrollmentFlowTest extends SdkLiveBase {

  static final String FIXTURE = "SOVRA-FIXTURE/v1\nname: Ana Example\n"
      + "document_number: X1234567\ndate_of_birth: 1990-01-02\ncountry: NL\n";

  @Test
  void enrollmentCustodyQuickstart() throws Exception {
    MachineAccount maker = mintAccount("sdk-enr-maker", "ISSUER_OPS");
    MachineAccount checker = mintAccount("sdk-enr-checker", "ISSUER_OPS");
    MachineAccount admin = mintAccount("sdk-enr-admin", "TRUST_ADMIN");
    ObjectMapper mapper = new ObjectMapper();
    TestHolders.HolderKeys holder = TestHolders.generate(mapper);
    TestHolders.HolderKeys fresh = TestHolders.generate(mapper);
    try (SovraClient makerClient = clientFor(maker.token());
        SovraClient checkerClient = clientFor(checker.token());
        SovraClient adminClient = clientFor(admin.token())) {
      // Source to approved extraction.
      VaultClient.StoredVersion stored = makerClient.vault.store(
          "https://issuer.example/sdk-enrollment", "sdk enrollment source",
          List.of("extraction-run"), FIXTURE.getBytes(StandardCharsets.UTF_8));
      VaultClient.GrantView grant = makerClient.vault.grant(
          stored.objectId(), 1, "service_account", null, "extraction-run", "sdk-test", 3600);
      ExtractionClient.RunResult run = makerClient.extraction.run(
          stored.objectId(), 1, grant.grantId(), "extraction-run", "sdk-test",
          "fixture-doc-v1");
      makerClient.extraction.approve(run.recordId(), 1);

      // Case to approval.
      EnrollmentClient.Created created = makerClient.enrollment.create(
          stored.objectId(), run.recordId(), holder.jwk());
      assertThat(created.state()).isEqualTo("PENDING");
      makerClient.enrollment.submit(created.enrollmentId());
      EnrollmentClient.DecisionView decided = checkerClient.enrollment.decide(
          created.enrollmentId(), 1, "approve",
          TestHolders.proofOver(holder,
              "enrollment-binding\n" + created.enrollmentId() + "\n1"));
      assertThat(decided.state()).isEqualTo("APPROVED");
      EnrollmentClient.EligibilityView eligibility =
          makerClient.enrollment.eligibility(created.enrollmentId());
      assertThat(eligibility.eligible()).isTrue();
      assertThat(eligibility.claims().get("adultOver18")).isEqualTo("true");

      // Custody: report, then recover under an admin.
      CustodyClient.Reported reported = makerClient.custody.report(
          TestHolders.thumbprint(holder), "loss");
      assertThat(reported.revokedCredentials()).isZero();
      CustodyClient.Recovered recovered = adminClient.custody.recover(
          reported.recoveryId(), fresh.jwk(),
          TestHolders.proofOver(fresh, "holder-recovery\n" + reported.recoveryId() + "\n"
              + TestHolders.thumbprint(fresh)));
      assertThat(recovered.newThumbprint()).isEqualTo(TestHolders.thumbprint(fresh));
      CustodyClient.KeyView key = makerClient.custody.get(reported.keyId());
      assertThat(key.status()).isEqualTo("COMPROMISED");
      assertThat(key.recoveries()).hasSize(1);
      // The case queue lists the approved case with current eligibility.
      EnrollmentClient.EnrollmentPage queue =
          makerClient.enrollment.list("approved", 50, null);
      assertThat(queue.items().stream().map(EnrollmentClient.EnrollmentSummary::enrollmentId))
          .contains(created.enrollmentId());
    }
  }
}
