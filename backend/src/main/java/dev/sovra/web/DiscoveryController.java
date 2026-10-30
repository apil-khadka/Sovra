package dev.sovra.web;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public capability discovery (SOV-022): the one document an
 * integrator reads before anything else. Profile, contract,
 * sandbox rules, SDK compatibility, and the RP read boundary —
 * all static posture, no identity data, no authentication.
 * {@code CONTRACT_VERSION} moves with
 * {@code docs/engineering/implemented-api.openapi.yaml}; both
 * SDK {@code SUPPORTED_CONTRACT} constants follow it.
 */
@RestController
@RequestMapping("/api/discovery")
public class DiscoveryController {

  static final String CONTRACT_VERSION = "0.16.0";
  static final String SDK_VERSION = "0.16.0";

  private final String version;
  private final String profile;

  public DiscoveryController(
      @Value("${sovra.version}") String version,
      @Value("${sovra.profile:synthetic}") String profile) {
    this.version = version;
    this.profile = profile;
  }

  @GetMapping
  public ResponseEntity<Map<String, Object>> discovery() {
    Map<String, Object> sandbox = new LinkedHashMap<>();
    sandbox.put("namePattern", "sandbox-<app>");
    sandbox.put("roles", List.of("RP_CLIENT"));
    sandbox.put("ttlHours", 24);
    sandbox.put("demoProfiles", List.of("synthetic", "sdjwt-vc"));

    Map<String, Object> sdks = new LinkedHashMap<>();
    sdks.put("java", SDK_VERSION);
    sdks.put("typescript", SDK_VERSION);

    Map<String, Object> rpReads = new LinkedHashMap<>();
    rpReads.put("outcomes", "own submitted decisions unless TENANT_MEMBER");
    rpReads.put("credentials", "members manage RP_CLIENT-bearing accounts only");

    Map<String, Object> body = new LinkedHashMap<>();
    body.put("service", "sovra-backend");
    body.put("version", version);
    body.put("profile", profile);
    body.put("contractVersion", CONTRACT_VERSION);
    body.put("auth", List.of("Bearer service-account", "BFF session"));
    body.put("sandbox", sandbox);
    body.put("sdks", sdks);
    body.put("rp", rpReads);
    return ResponseEntity.ok(body);
  }
}
