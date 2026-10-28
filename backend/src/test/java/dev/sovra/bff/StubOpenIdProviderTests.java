package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import dev.sovra.crypto.HolderProofs;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * The stub OP is the oracle every BFF login test trusts: it must
 * mint genuinely valid ID tokens (signature verifies against the
 * served JWKS, claims decode) and genuinely enforce S256 PKCE. A
 * broken harness would green-light a broken login, so the harness
 * itself is pinned here.
 */
class StubOpenIdProviderTests {

  StubOpenIdProvider stub;
  HttpClient http;
  ObjectMapper mapper = new ObjectMapper();

  @BeforeEach
  void setup() throws Exception {
    stub = new StubOpenIdProvider("sovra-bff", "stub-secret");
    http = HttpClient.newBuilder().followRedirects(Redirect.NEVER).build();
  }

  @AfterEach
  void teardown() {
    stub.close();
  }

  private String authorize(String challenge) throws Exception {
    String url = stub.baseUrl() + "/authorize?client_id=sovra-bff"
        + "&redirect_uri=" + URLEncoder.encode("http://localhost:18082/login/oauth2/code/sovra", StandardCharsets.UTF_8)
        + "&state=test-state&nonce=test-nonce"
        + (challenge == null ? "" : "&code_challenge=" + challenge + "&code_challenge_method=S256");
    HttpResponse<String> response = http.send(
        HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build(),
        HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(302);
    String location = response.headers().firstValue("location").orElseThrow();
    return location.split("code=", 2)[1].split("&", 2)[0];
  }

  private HttpResponse<String> token(String code, String verifier) throws Exception {
    String body = "grant_type=authorization_code&code=" + code
        + "&redirect_uri=" + URLEncoder.encode("http://localhost:18082/login/oauth2/code/sovra", StandardCharsets.UTF_8)
        + (verifier == null ? "" : "&code_verifier=" + verifier);
    String basic = java.util.Base64.getEncoder()
        .encodeToString("sovra-bff:stub-secret".getBytes(StandardCharsets.UTF_8));
    return http.send(
        HttpRequest.newBuilder(URI.create(stub.baseUrl() + "/token"))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", "Basic " + basic)
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build(),
        HttpResponse.BodyHandlers.ofString());
  }

  @Test
  void mintedTokenVerifiesAgainstServedJwks() throws Exception {
    stub.script(new StubOpenIdProvider.Script(
        "alice", List.of("sovra-members"), "sovra-demo", List.of("pwd")));
    // RFC 7636 appendix B test vector.
    String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    String challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    String code = authorize(challenge);
    HttpResponse<String> response = token(code, verifier);
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(stub.pkceVerified()).isTrue();
    JsonNode body = mapper.readTree(response.body());

    SignedJWT jwt = SignedJWT.parse(body.get("id_token").asString());
    assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
    assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo(stub.issuer());
    assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("alice");
    assertThat(jwt.getJWTClaimsSet().getAudience()).contains("sovra-bff");
    assertThat(jwt.getJWTClaimsSet().getStringClaim("nonce")).isEqualTo("test-nonce");

    // Verify against the SERVED JWKS, not the stub's key handle.
    HttpResponse<String> jwksResponse = http.send(
        HttpRequest.newBuilder(URI.create(stub.baseUrl() + "/jwks"))
            .timeout(Duration.ofSeconds(10)).GET().build(),
        HttpResponse.BodyHandlers.ofString());
    JsonNode key = mapper.readTree(jwksResponse.body()).get("keys").get(0);
    ECPublicKey publicKey = HolderProofs.parseP256Key(key);
    JWSVerifier verifierKey = new ECDSAVerifier(publicKey);
    assertThat(jwt.verify(verifierKey)).isTrue();
  }

  @Test
  void wrongVerifierAndMissingPkceRefused() throws Exception {
    stub.script(new StubOpenIdProvider.Script(
        "bob", List.of("sovra-members"), "sovra-demo", List.of("pwd")));
    String code = authorize("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    assertThat(token(code, "wrong-verifier").statusCode()).isEqualTo(400);
    assertThat(stub.pkceVerified()).isFalse();

    HttpResponse<String> noPkce = http.send(
        HttpRequest.newBuilder(URI.create(stub.baseUrl()
                + "/authorize?client_id=sovra-bff&redirect_uri=http://x/&state=s&nonce=n"))
            .timeout(Duration.ofSeconds(10)).GET().build(),
        HttpResponse.BodyHandlers.ofString());
    assertThat(noPkce.statusCode()).isEqualTo(400);
  }

}
