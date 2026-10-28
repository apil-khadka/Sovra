package dev.sovra.bff;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.sovra.issuance.IssuanceFixtures;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import tools.jackson.databind.ObjectMapper;

/**
 * Scriptable OpenID Provider for BFF login tests (SOV-006). Serves
 * discovery, JWKS, an auto-approving authorize endpoint, a token
 * endpoint that genuinely verifies S256 PKCE, and userinfo. No new
 * test dependencies: JDK HTTP server plus the Nimbus JOSE the backend
 * already ships.
 */
public final class StubOpenIdProvider implements AutoCloseable {

  /** Claims minted into the next ID token; scripted per test. */
  public record Script(
      String subject,
      String preferredUsername,
      List<String> groups,
      String tenantSlug,
      List<String> amr,
      String issuerOverride,
      String audienceOverride) {
    public Script(String subject, List<String> groups, String tenantSlug, List<String> amr) {
      this(subject, subject, groups, tenantSlug, amr, null, null);
    }

    public Script(String subject, List<String> groups, String tenantSlug, List<String> amr,
        String issuerOverride, String audienceOverride) {
      this(subject, subject, groups, tenantSlug, amr, issuerOverride, audienceOverride);
    }
  }

  private record Pending(String nonce, String challenge, String redirectUri) {}

  private final HttpServer server;
  private final ObjectMapper mapper = new ObjectMapper();
  private final ECPrivateKey privateKey;
  private final ECPublicKey publicKey;
  private final String clientId;
  private final String clientSecret;
  private final Map<String, Pending> pending = new ConcurrentHashMap<>();
  private final AtomicReference<Script> script = new AtomicReference<>();
  private volatile boolean pkceVerified;
  private volatile String lastChallengeMethod;

  public StubOpenIdProvider(String clientId, String clientSecret) throws Exception {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair pair = generator.generateKeyPair();
    this.privateKey = (ECPrivateKey) pair.getPrivate();
    this.publicKey = (ECPublicKey) pair.getPublic();
    this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    this.server.setExecutor(Executors.newCachedThreadPool());
    server.createContext("/.well-known/openid-configuration", this::discovery);
    server.createContext("/jwks", this::jwks);
    server.createContext("/authorize", this::authorize);
    server.createContext("/token", this::token);
    server.createContext("/userinfo", this::userinfo);
    server.start();
  }

  public String baseUrl() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  public String issuer() {
    return baseUrl();
  }

  public void script(Script next) {
    pkceVerified = false;
    lastChallengeMethod = null;
    script.set(next);
  }

  /** True once a token call verified its S256 code_verifier. */
  public boolean pkceVerified() {
    return pkceVerified;
  }

  public String lastChallengeMethod() {
    return lastChallengeMethod;
  }

  @Override
  public void close() {
    server.stop(0);
  }

  private void discovery(HttpExchange exchange) throws IOException {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("issuer", issuer());
    body.put("authorization_endpoint", baseUrl() + "/authorize");
    body.put("token_endpoint", baseUrl() + "/token");
    body.put("userinfo_endpoint", baseUrl() + "/userinfo");
    body.put("jwks_uri", baseUrl() + "/jwks");
    body.put("response_types_supported", List.of("code"));
    body.put("subject_types_supported", List.of("public"));
    body.put("id_token_signing_alg_values_supported", List.of("ES256"));
    body.put("code_challenge_methods_supported", List.of("S256"));
    json(exchange, 200, body);
  }

  private void jwks(HttpExchange exchange) throws IOException {
    Map<String, Object> key = new LinkedHashMap<>();
    key.put("kty", "EC");
    key.put("crv", "P-256");
    key.put("x", base64Url(publicKey.getW().getAffineX()));
    key.put("y", base64Url(publicKey.getW().getAffineY()));
    key.put("kid", "stub-1");
    key.put("use", "sig");
    key.put("alg", "ES256");
    json(exchange, 200, Map.of("keys", List.of(key)));
  }

  private void authorize(HttpExchange exchange) throws IOException {
    Map<String, String> query = form(exchange.getRequestURI().getRawQuery());
    if (!clientId.equals(query.get("client_id")) || query.get("redirect_uri") == null
        || query.get("state") == null || query.get("nonce") == null) {
      text(exchange, 400, "bad authorization request");
      return;
    }
    lastChallengeMethod = query.get("code_challenge_method");
    if (!"S256".equals(lastChallengeMethod) || query.get("code_challenge") == null) {
      text(exchange, 400, "S256 PKCE required");
      return;
    }
    String code = "stub-" + UUID.randomUUID();
    pending.put(code, new Pending(
        query.get("nonce"), query.get("code_challenge"), query.get("redirect_uri")));
    redirect(exchange, query.get("redirect_uri") + "?code=" + code + "&state=" + query.get("state"));
  }

  private void token(HttpExchange exchange) throws IOException {
    try {
      if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
        text(exchange, 405, "method not allowed");
        return;
      }
      Map<String, String> form = form(new String(
          exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
      if (!"authorization_code".equals(form.get("grant_type"))) {
        text(exchange, 400, "unsupported grant");
        return;
      }
      if (!authorized(exchange, form)) {
        text(exchange, 401, "bad client credentials");
        return;
      }
      Pending held = pending.remove(form.get("code"));
      if (held == null || !held.redirectUri().equals(form.get("redirect_uri"))) {
        text(exchange, 400, "unknown code");
        return;
      }
      String verifier = form.get("code_verifier");
      if (verifier == null || !s256(verifier).equals(held.challenge())) {
        text(exchange, 400, "PKCE verification failed");
        return;
      }
      pkceVerified = true;
      Script current = script.get();
      if (current == null) {
        text(exchange, 400, "no scripted identity");
        return;
      }
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("id_token", idToken(current, held.nonce()));
      body.put("access_token", "stub-access");
      body.put("token_type", "Bearer");
      body.put("expires_in", 300);
      json(exchange, 200, body);
    } catch (Exception e) {
      text(exchange, 500, "stub failure: " + e.getMessage());
    }
  }

  private void userinfo(HttpExchange exchange) throws IOException {
    String auth = exchange.getRequestHeaders().getFirst("Authorization");
    Script current = script.get();
    if (!"Bearer stub-access".equals(auth) || current == null) {
      text(exchange, 401, "unauthorized");
      return;
    }
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("sub", current.subject());
    body.put("preferred_username", current.preferredUsername());
    body.put("groups", current.groups());
    body.put("tenant_slug", current.tenantSlug());
    json(exchange, 200, body);
  }

  private boolean authorized(HttpExchange exchange, Map<String, String> form) {
    String auth = exchange.getRequestHeaders().getFirst("Authorization");
    if (auth != null && auth.startsWith("Basic ")) {
      String decoded = new String(
          Base64.getDecoder().decode(auth.substring("Basic ".length())), StandardCharsets.UTF_8);
      return (clientId + ":" + clientSecret).equals(decoded);
    }
    return clientId.equals(form.get("client_id")) && clientSecret.equals(form.get("client_secret"));
  }

  private String idToken(Script current, String nonce) throws Exception {
    Instant now = Instant.now();
    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
        .issuer(current.issuerOverride() == null ? issuer() : current.issuerOverride())
        .subject(current.subject())
        .audience(current.audienceOverride() == null ? clientId : current.audienceOverride())
        .expirationTime(Date.from(now.plusSeconds(300)))
        .issueTime(Date.from(now))
        .claim("nonce", nonce)
        .claim("auth_time", now.getEpochSecond())
        .claim("preferred_username", current.preferredUsername())
        .claim("groups", current.groups())
        .claim("tenant_slug", current.tenantSlug())
        .claim("amr", current.amr());
    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("stub-1").build(), claims.build());
    jwt.sign(new ECDSASigner(privateKey));
    return jwt.serialize();
  }

  private static String s256(String verifier) throws Exception {
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    byte[] digest = sha256.digest(verifier.getBytes(StandardCharsets.US_ASCII));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
  }

  private static String base64Url(BigInteger value) {
    return IssuanceFixtures.base64UrlUnsigned(value);
  }

  private static Map<String, String> form(String raw) {
    Map<String, String> parsed = new HashMap<>();
    if (raw == null || raw.isBlank()) {
      return parsed;
    }
    for (String pair : raw.split("&")) {
      int at = pair.indexOf('=');
      if (at > 0) {
        parsed.put(
            URLDecoder.decode(pair.substring(0, at), StandardCharsets.UTF_8),
            URLDecoder.decode(pair.substring(at + 1), StandardCharsets.UTF_8));
      }
    }
    return parsed;
  }

  private void json(HttpExchange exchange, int status, Object body) throws IOException {
    byte[] raw = mapper.writeValueAsBytes(body);
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, raw.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(raw);
    }
  }

  private static void text(HttpExchange exchange, int status, String body) throws IOException {
    byte[] raw = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, raw.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(raw);
    }
  }

  private static void redirect(HttpExchange exchange, String location) throws IOException {
    exchange.getResponseHeaders().set("Location", location);
    exchange.sendResponseHeaders(302, -1);
    exchange.close();
  }
}
