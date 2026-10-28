package dev.sovra.bff;

import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * BFF trust registry (SOV-006, SOV-004 section 4). Every value is an
 * exact allowlist entry: the OP issuer, our client id (audience),
 * redirect URIs, tenant slugs, group-to-role map, and the
 * hardware-bound AMR methods that unlock privileged roles. Startup
 * fails fast on any blank, insecure, or Spring-registration-mismatched
 * value (see {@link BffConfigValidator}).
 */
@ConfigurationProperties(prefix = "sovra.bff")
public record BffProperties(
    boolean enabled,
    String issuer,
    String clientId,
    String redirectUri,
    String postLogoutRedirectUri,
    String endSessionEndpoint,
    boolean requireHttpsIssuer,
    String tenantClaim,
    String groupsClaim,
    List<String> allowedTenantSlugs,
    Map<String, String> groupRoleMap,
    List<String> privilegedRoles,
    List<String> hardwareAmr,
    @DefaultValue("sovra") String registrationId) {

  /** Fails fast unless the registry is complete and secure. */
  public void validateSelf() {
    if (!enabled) {
      return;
    }
    requireText(issuer, "issuer");
    requireText(clientId, "client-id");
    requireText(redirectUri, "redirect-uri");
    requireText(postLogoutRedirectUri, "post-logout-redirect-uri");
    requireText(endSessionEndpoint, "end-session-endpoint");
    requireText(tenantClaim, "tenant-claim");
    requireText(groupsClaim, "groups-claim");
    if (allowedTenantSlugs == null || allowedTenantSlugs.isEmpty()) {
      throw new IllegalStateException("sovra.bff.allowed-tenant-slugs must not be empty");
    }
    if (groupRoleMap == null || groupRoleMap.isEmpty()) {
      throw new IllegalStateException("sovra.bff.group-role-map must not be empty");
    }
    if (privilegedRoles == null || privilegedRoles.isEmpty()) {
      throw new IllegalStateException("sovra.bff.privileged-roles must not be empty");
    }
    if (hardwareAmr == null || hardwareAmr.isEmpty()) {
      throw new IllegalStateException("sovra.bff.hardware-amr must not be empty");
    }
    // Backchannel endpoints (issuer discovery, end-session) may go
    // plain http only when the demo escape hatch is explicit; browser
    // redirects are https-or-loopback unconditionally.
    requireBackchannelScheme(issuer, "issuer", requireHttpsIssuer);
    requireHttpsOrLocalhost(redirectUri, "redirect-uri");
    requireHttpsOrLocalhost(postLogoutRedirectUri, "post-logout-redirect-uri");
    requireBackchannelScheme(endSessionEndpoint, "end-session-endpoint", requireHttpsIssuer);
  }

  private static void requireText(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalStateException("sovra.bff." + name + " must not be blank");
    }
  }

  private static void requireBackchannelScheme(String uri, String name, boolean requireHttps) {
    String lower = uri.toLowerCase();
    if (lower.startsWith("https://") || lower.startsWith("http://")) {
      if (!requireHttps || lower.startsWith("https://") || isLoopback(lower)) {
        return;
      }
    }
    throw new IllegalStateException(
        "sovra.bff." + name + " must be https (loopback http allowed)");
  }

  private static void requireHttpsOrLocalhost(String uri, String name) {
    String lower = uri.toLowerCase();
    if (lower.startsWith("https://") || isLoopback(lower)) {
      return;
    }
    throw new IllegalStateException(
        "sovra.bff." + name + " must be https (loopback http allowed)");
  }

  private static boolean isLoopback(String lowerUri) {
    return lowerUri.startsWith("http://localhost/")
        || lowerUri.startsWith("http://localhost:")
        || lowerUri.startsWith("http://127.0.0.1/")
        || lowerUri.startsWith("http://127.0.0.1:");
  }
}
