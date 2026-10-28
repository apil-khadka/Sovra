package dev.sovra.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.TestAccounts.TestAccount;
import dev.sovra.consent.ConsentFixtures;
import dev.sovra.issuance.IssuanceFixtures;
import dev.sovra.trust.TrustService;
import dev.sovra.verification.VerificationFixtures;
import dev.sovra.verification.VerificationFixtures.Stage;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * ETag preconditions on stable reads (SOV-015, IF-11): consent reviews
 * and verification decisions emit strong tags, honor
 * {@code If-None-Match} with 304, and invalidate the review tag when the
 * derived state changes. 404s stay tagless (no existence oracle).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EtagPreconditionTests extends SovraAppRoleBase {

  @LocalServerPort int port;

  @Autowired TrustService trust;

  @Autowired ObjectMapper mapper;

  RestClient client;
  JdbcTemplate owner;

  private static final ParameterizedTypeReference<Map<String, Object>> VIEW =
      new ParameterizedTypeReference<>() {};

  @BeforeEach
  void setup() throws Exception {
    client = RestClient.builder().baseUrl("http://localhost:" + port).build();
    owner = new JdbcTemplate(ownerDataSource());
    IssuanceFixtures.ensureSyntheticIssuer(owner, trust, mapper);
  }

  @SuppressWarnings("unchecked")
  private ResponseEntity<Map<String, Object>> reviewRaw(TestAccount viewer, String requestId) {
    return client
        .get()
        .uri("/api/consent/requests/" + requestId)
        .headers(viewer.headers())
        .retrieve()
        .toEntity(VIEW);
  }

  @Test
  void consentReviewHonorsIfNoneMatchAndInvalidatesOnDecision() throws Exception {
    Stage stage =
        VerificationFixtures.approvedStage(client, owner, mapper, "etag-" + UUID.randomUUID());
    // Fresh pending request for the state-change half of the test.
    String credentialId =
        ConsentFixtures.issueCredential(client, stage.issuer(), stage.holder(), mapper);
    Map<String, Object> created = ConsentFixtures.create(
        client, stage.rp(), ConsentFixtures.createBody(UUID.fromString(credentialId)));
    assertThat(created).isNotNull();
    String requestId = created.get("requestId").toString();

    ResponseEntity<Map<String, Object>> first = reviewRaw(stage.rp(), requestId);
    String etag = first.getHeaders().getETag();
    assertThat(etag).isNotBlank();
    assertThat(first.getBody().get("state")).isEqualTo("PENDING");

    ResponseEntity<Void> cached =
        client
            .get()
            .uri("/api/consent/requests/" + requestId)
            .headers(
                h -> {
                  stage.rp().headers().accept(h);
                  h.setIfNoneMatch(etag);
                })
            .retrieve()
            .toBodilessEntity();
    assertThat(cached.getStatusCode()).isEqualTo(HttpStatusCode.valueOf(304));

    // The holder's decision changes the derived state, hence the tag.
    Map<String, Object> review = ConsentFixtures.review(client, stage.rp(), requestId);
    ConsentFixtures.decide(
        client,
        stage.holderAgent(),
        requestId,
        ConsentFixtures.decideBody(stage.holder(), review, "approve", mapper));
    ResponseEntity<Map<String, Object>> reread = reviewRaw(stage.rp(), requestId);
    assertThat(reread.getBody().get("state")).isEqualTo("VERIFIED");
    assertThat(reread.getHeaders().getETag()).isNotBlank().isNotEqualTo(etag);
  }

  @Test
  void verificationDecisionTagIsStable() throws Exception {
    Stage stage =
        VerificationFixtures.approvedStage(client, owner, mapper, "etagv-" + UUID.randomUUID());
    Map<String, Object> submitted =
        VerificationFixtures.verify(
            client,
            stage.rp(),
            VerificationFixtures.verifyBody(
                stage.holder(),
                stage.requestId(),
                VerificationFixtures.nonce(),
                ConsentFixtures.AUDIENCE,
                mapper));
    assertThat(submitted).isNotNull();
    String decisionId = submitted.get("decisionId").toString();

    ResponseEntity<Map<String, Object>> first =
        client
            .get()
            .uri("/api/verification/decisions/" + decisionId)
            .headers(stage.rp().headers())
            .retrieve()
            .toEntity(VIEW);
    String etag = first.getHeaders().getETag();
    assertThat(etag).isNotBlank();

    ResponseEntity<Map<String, Object>> second =
        client
            .get()
            .uri("/api/verification/decisions/" + decisionId)
            .headers(stage.rp().headers())
            .retrieve()
            .toEntity(VIEW);
    assertThat(second.getHeaders().getETag()).isEqualTo(etag);

    ResponseEntity<Void> cached =
        client
            .get()
            .uri("/api/verification/decisions/" + decisionId)
            .headers(
                h -> {
                  stage.rp().headers().accept(h);
                  h.setIfNoneMatch(etag);
                })
            .retrieve()
            .toBodilessEntity();
    assertThat(cached.getStatusCode()).isEqualTo(HttpStatusCode.valueOf(304));
  }

  @Test
  void missingObjectsStayTagless() {
    TestAccount viewer =
        dev.sovra.TestAccounts.create(owner, "etag-404", Set.of("TENANT_MEMBER"));
    String missing = UUID.randomUUID().toString();
    assertThatThrownBy(() -> reviewRaw(viewer, missing))
        .isInstanceOfSatisfying(
            HttpClientErrorException.NotFound.class,
            e -> assertThat(e.getResponseHeaders().getETag()).isNull());
    assertThatThrownBy(
            () ->
                client
                    .get()
                    .uri("/api/verification/decisions/" + missing)
                    .headers(viewer.headers())
                    .retrieve()
                    .toBodilessEntity())
        .isInstanceOfSatisfying(
            HttpClientErrorException.NotFound.class,
            e -> assertThat(e.getResponseHeaders().getETag()).isNull());
  }
}
