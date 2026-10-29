package dev.sovra.openid;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.web.CurrentPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;

/**
 * OpenID4VCI endpoints (SOV-036). Offer publication and the synthetic
 * authorization server need a service account; token, nonce, and
 * credential calls are public wallet calls bound to single-use
 * grants. Error bodies are OAuth2 {@code error} codes without
 * distinguishing detail.
 */
@RestController
@RequestMapping("/api/vci")
public class VciController {

  private final VciService vci;

  public VciController(VciService vci) {
    this.vci = vci;
  }

  @PostMapping("/offers")
  public ResponseEntity<String> offer(@Valid @RequestBody OfferRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return json(vci.createOffer(caller, request.issuerId(), request.vct()));
  }

  @PostMapping("/authorize")
  public ResponseEntity<String> authorize(@Valid @RequestBody AuthorizeRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    return json(
        vci.authorize(caller, request.issuerId(), request.vct(), request.codeChallenge()));
  }

  @PostMapping(
      value = "/token",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  public ResponseEntity<String> token(@RequestParam MultiValueMap<String, String> form) {
    return json(
        vci.token(
            first(form, "grant_type"), first(form, "pre-authorized_code") != null
                ? first(form, "pre-authorized_code") : first(form, "code"),
            first(form, "code_verifier")));
  }

  /** JSON convenience variant of the token endpoint for harness clients. */
  @PostMapping(value = "/token", consumes = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> tokenJson(@RequestBody Map<String, String> body) {
    String code = body.get("pre-authorized_code") != null
        ? body.get("pre-authorized_code") : body.get("code");
    return json(vci.token(body.get("grant_type"), code, body.get("code_verifier")));
  }

  @PostMapping("/nonce")
  public ResponseEntity<String> nonce(
      @RequestHeader(value = "Authorization", required = false) String authorization) {
    return json(vci.refreshNonce(authorization));
  }

  @PostMapping("/credential")
  public ResponseEntity<String> credential(
      @RequestHeader(value = "Authorization", required = false) String authorization,
      @RequestBody JsonNode body) {
    return json(vci.credential(authorization, body));
  }

  private static ResponseEntity<String> json(String body) {
    return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(body);
  }

  private static String first(MultiValueMap<String, String> form, String key) {
    return form.getFirst(key);
  }

  public record OfferRequest(@NotNull String issuerId, @NotNull String vct) {}

  public record AuthorizeRequest(
      @NotNull String issuerId, @NotNull String vct, @NotNull String codeChallenge) {}
}
