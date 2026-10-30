package dev.sovra.sdk;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Application credential lifecycle (TRUST_ADMIN). Tokens appear once, in create/rotate bodies. */
public final class AuthClient {

  private final SovraClient client;

  AuthClient(SovraClient client) {
    this.client = client;
  }

  public record ServiceAccount(
      String id,
      String name,
      List<String> roles,
      boolean revoked,
      String expiresAt,
      String createdAt) {}

  public record ServiceAccountWithToken(
      String id,
      String name,
      List<String> roles,
      boolean revoked,
      String expiresAt,
      String createdAt,
      String token) {}

  public ServiceAccountWithToken create(String name, List<String> roles, String expiresAt) {
    Map<String, Object> body = new HashMap<>();
    body.put("name", name);
    body.put("roles", roles);
    if (expiresAt != null) {
      body.put("expiresAt", expiresAt);
    }
    return client.post("/api/auth/service-accounts", body, ServiceAccountWithToken.class);
  }

  public List<ServiceAccount> list() {
    return client.get("/api/auth/service-accounts", ServiceAccountList.class);
  }

  public ServiceAccount get(String id) {
    return client.get("/api/auth/service-accounts/" + id, ServiceAccount.class);
  }

  public ServiceAccountWithToken rotate(String id, String expiresAt) {
    Map<String, Object> body = new HashMap<>();
    if (expiresAt != null) {
      body.put("expiresAt", expiresAt);
    }
    return client.post(
        "/api/auth/service-accounts/" + id + "/rotate", body, ServiceAccountWithToken.class);
  }

  /** Idempotent terminal revocation. */
  public ServiceAccount revoke(String id) {
    return client.post(
        "/api/auth/service-accounts/" + id + "/revoke", Map.of(), ServiceAccount.class);
  }

  public static final class ServiceAccountList extends java.util.ArrayList<ServiceAccount> {}
}
