package dev.sovra.openid;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.web.CurrentPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * OpenID4VP endpoints (SOV-036). Session creation needs the consuming
 * RP's service account; the request object, JWKS, and response
 * submission are public wallet calls. Responses must be
 * {@code direct_post.jwt} JWEs; plain {@code direct_post} is rejected
 * outside loopback harness runs.
 */
@RestController
@RequestMapping("/api/vp")
public class VpController {

  private final VpService vp;

  public VpController(VpService vp) {
    this.vp = vp;
  }

  @PostMapping("/requests")
  public ResponseEntity<String> create(@Valid @RequestBody CreateRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return json(vp.createRequest(caller, request.proofRequestId()));
  }

  @GetMapping("/requests/{id}/object")
  public ResponseEntity<String> requestObject(@PathVariable("id") UUID sessionId) {
    // Signed request-object JWT, served verbatim for the wallet fetch.
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType("application/oauth-authz-req+jwt"))
        .body(vp.requestObject(sessionId));
  }

  @GetMapping("/jwks.json")
  public ResponseEntity<String> jwks() {
    return json(vp.jwks());
  }

  /** Form-encoded {@code direct_post.jwt} (the interoperable shape). */
  @PostMapping(
      value = "/responses/{id}",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  public ResponseEntity<String> respondForm(
      @PathVariable("id") UUID sessionId,
      @RequestParam MultiValueMap<String, String> form,
      HttpServletRequest request) {
    return json(
        vp.submitResponse(
            sessionId,
            form.getFirst("response"),
            form.getFirst("vp_token"),
            form.getFirst("presentation_submission"),
            loopback(request)));
  }

  /** JSON convenience variant for harness clients. */
  @PostMapping(value = "/responses/{id}", consumes = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> respondJson(
      @PathVariable("id") UUID sessionId,
      @RequestBody Map<String, Object> body,
      HttpServletRequest request) {
    Object submission = body.get("presentation_submission");
    String submissionRaw;
    if (submission instanceof String text) {
      submissionRaw = text;
    } else if (submission instanceof Map<?, ?> object) {
      try {
        submissionRaw =
            new tools.jackson.databind.ObjectMapper().writeValueAsString(object);
      } catch (Exception e) {
        throw new InvalidOpenIdRequestException("submission is malformed");
      }
    } else {
      submissionRaw = null;
    }
    Object response = body.get("response");
    Object vpToken = body.get("vp_token");
    return json(
        vp.submitResponse(
            sessionId,
            response instanceof String text ? text : null,
            vpToken instanceof String text ? text : null,
            submissionRaw,
            loopback(request)));
  }

  private static ResponseEntity<String> json(String body) {
    return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(body);
  }

  private static boolean loopback(HttpServletRequest request) {
    String remote = request.getRemoteAddr();
    return "127.0.0.1".equals(remote) || "::1".equals(remote) || "0:0:0:0:0:0:0:1".equals(remote);
  }

  public record CreateRequest(@NotNull UUID proofRequestId) {}
}
