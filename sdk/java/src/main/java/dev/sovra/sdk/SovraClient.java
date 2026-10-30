package dev.sovra.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Sovra machine-API client (SOV-021, OD-16). One client talks to
 * one base URL: HTTPS, except plain HTTP to loopback for local
 * demos. The token lives in memory only and is stripped from any
 * message the client builds. Reads retry at most three times on
 * transport failure or 503; writes never retry automatically —
 * callers replay idempotent operations with the original key.
 */
public final class SovraClient implements AutoCloseable {

  /** API contract version this SDK targets. */
  public static final String SUPPORTED_CONTRACT = "0.16.0";

  private static final int MAX_READ_ATTEMPTS = 3;

  private final String baseUrl;
  private final String token;
  private final HttpClient http;
  private final ObjectMapper mapper = new ObjectMapper();

  public final OpsClient ops;
  public final TrustClient trust;
  public final AuthClient auth;
  public final IssuanceClient issuance;
  public final ConsentClient consent;
  public final VerificationClient verification;
  public final VaultClient vault;
  public final QuarantineClient quarantine;
  public final ExtractionClient extraction;
  public final EnrollmentClient enrollment;
  public final CustodyClient custody;

  public SovraClient(String baseUrl, String token) {
    this(baseUrl, token, Duration.ofSeconds(30));
  }

  public SovraClient(String baseUrl, String token, Duration timeout) {
    this.baseUrl = validatedBase(baseUrl);
    if (token == null || token.isBlank()) {
      throw new IllegalArgumentException("token is required");
    }
    this.token = token;
    this.http =
        HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER)
            .build();
    this.ops = new OpsClient(this);
    this.trust = new TrustClient(this);
    this.auth = new AuthClient(this);
    this.issuance = new IssuanceClient(this);
    this.consent = new ConsentClient(this);
    this.verification = new VerificationClient(this);
    this.vault = new VaultClient(this);
    this.quarantine = new QuarantineClient(this);
    this.extraction = new ExtractionClient(this);
    this.enrollment = new EnrollmentClient(this);
    this.custody = new CustodyClient(this);
  }

  static String validatedBase(String baseUrl) {
    URI uri;
    try {
      uri = URI.create(baseUrl == null ? "" : baseUrl.strip());
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("base URL is malformed");
    }
    String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
    String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase();
    boolean loopback =
        host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]");
    if ("https".equals(scheme) || ("http".equals(scheme) && loopback)) {
      String base = uri.toString();
      return base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
    }
    throw new IllegalArgumentException("base URL must be https, or http loopback for demos");
  }

  @Override
  public void close() {
    http.close();
  }

  public record Tagged<T>(T value, String etag) {}

  <T> T get(String path, Class<T> type) {
    return get(path, null, type).orElseThrow(() -> new SovraApiError(
        304, "not_modified", "server answered 304 without a precondition", false));
  }

  /**
   * Conditional-read primitive: fetches the path with an optional
   * precondition and returns the value with its ETag. Empty when
   * the server answers 304.
   */
  public <T> java.util.Optional<Tagged<T>> getTagged(
      String path, String ifNoneMatch, Class<T> type) {
    HttpRequest.Builder builder = authed(path).GET();
    if (ifNoneMatch != null) {
      builder.header("If-None-Match", ifNoneMatch);
    }
    try {
      HttpResponse<String> response =
          http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() == 304) {
        return java.util.Optional.empty();
      }
      String etag = response.headers().firstValue("ETag").orElse("");
      return java.util.Optional.of(new Tagged<>(requireOk(response, type), etag));
    } catch (java.io.IOException e) {
      throw connectError(e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw connectError(e);
    }
  }

  <T> Optional<T> get(String path, String ifNoneMatch, Class<T> type) {
    HttpRequest.Builder builder = authed(path).GET();
    if (ifNoneMatch != null) {
      builder.header("If-None-Match", ifNoneMatch);
    }
    HttpRequest request = builder.build();
    int attempt = 0;
    while (true) {
      attempt++;
      try {
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 304) {
          return Optional.empty();
        }
        if (response.statusCode() == 503 && attempt < MAX_READ_ATTEMPTS) {
          backoff(attempt);
          continue;
        }
        return Optional.of(requireOk(response, type));
      } catch (IOException | InterruptedException e) {
        if (attempt >= MAX_READ_ATTEMPTS) {
          throw connectError(e);
        }
        backoff(attempt);
        if (e instanceof InterruptedException) {
          Thread.currentThread().interrupt();
          throw connectError(e);
        }
      }
    }
  }

  <T> T post(String path, Object body, Class<T> type) {
    return post(path, body, Map.of(), type);
  }

  <T> T post(String path, Object body, Map<String, String> headers, Class<T> type) {
    String json = writeJson(body);
    HttpRequest.Builder builder =
        authed(path)
            .POST(HttpRequest.BodyPublishers.ofString(json == null ? "" : json))
            .header("Content-Type", "application/json");
    headers.forEach(builder::header);
    try {
      HttpResponse<String> response =
          http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
      return requireOk(response, type);
    } catch (IOException e) {
      throw connectError(e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw connectError(e);
    }
  }

  private HttpRequest.Builder authed(String path) {
    return HttpRequest.newBuilder(URI.create(baseUrl + path))
        .timeout(Duration.ofSeconds(30))
        .header("Authorization", "Bearer " + token);
  }

  private <T> T requireOk(HttpResponse<String> response, Class<T> type) {
    if (response.statusCode() >= 200 && response.statusCode() < 300) {
      try {
        if (type == String.class) {
          return type.cast(response.body());
        }
        if (type == Void.class) {
          return null;
        }
        return mapper.readValue(response.body(), type);
      } catch (Exception e) {
        throw new SovraApiError(
            response.statusCode(), "decode_error", "response shape is not this SDK's contract",
            false);
      }
    }
    throw apiError(response);
  }

  private SovraApiError apiError(HttpResponse<String> response) {
    String code = "http_" + response.statusCode();
    String message = "backend responded " + response.statusCode();
    try {
      JsonNode node = mapper.readTree(response.body());
      if (node != null && node.isObject()) {
        JsonNode named =
            node.has("code") ? node.get("code")
                : node.has("title") ? node.get("title")
                    : node.has("error") ? node.get("error") : null;
        if (named != null && named.isString()) {
          code = named.asString();
        }
        JsonNode reason = node.get("reason");
        message = code + (reason != null && reason.isString() ? ":" + reason.asString() : "");
      }
    } catch (Exception ignored) {
      // Fall through with the generic shape.
    }
    boolean retryable = response.statusCode() == 503;
    return new SovraApiError(response.statusCode(), code, scrub(message), retryable);
  }

  private String writeJson(Object body) {
    if (body == null) {
      return null;
    }
    try {
      return mapper.writeValueAsString(body);
    } catch (Exception e) {
      throw new IllegalArgumentException("request body is not serializable");
    }
  }

  private SovraApiError connectError(Exception e) {
    return new SovraApiError(0, "connect_error", scrub("backend unreachable"), true);
  }

  private String scrub(String message) {
    return token.isEmpty() ? message : message.replace(token, "[redacted]");
  }

  private static void backoff(int attempt) {
    try {
      Thread.sleep(200L * attempt);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new SovraApiError(0, "connect_error", "backend unreachable", true);
    }
  }
}
