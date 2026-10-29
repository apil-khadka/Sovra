package dev.sovra.openid;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Public OpenID metadata documents (SOV-036). */
@RestController
public class OpenIdMetadataController {

  private final VciService vci;

  public OpenIdMetadataController(VciService vci) {
    this.vci = vci;
  }

  @GetMapping("/.well-known/openid-credential-issuer")
  public ResponseEntity<String> credentialIssuer() {
    return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(vci.metadata());
  }
}
