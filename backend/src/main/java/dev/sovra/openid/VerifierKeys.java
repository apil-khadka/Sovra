package dev.sovra.openid;

import java.util.Map;

/**
 * OpenID4VP verifier keys (PROD-005). Two implementations, never
 * both: the deterministic G1 fixture for synthetic demos, and
 * file-mounted versioned keys for production. Key separation is a
 * production property — signing and decryption use different keys
 * with different ids — while the G1 fixture documents its single
 * shared key as non-secret.
 */
public interface VerifierKeys {

  /** Signs an authorization request object (ES256, {@code kid} set). */
  String signRequestObject(Map<String, Object> claims);

  /**
   * Decrypts a {@code direct_post.jwt} JWE addressed to a verifier
   * decryption key. The header must name exactly the frozen
   * transport ({@code ECDH-ES+A256KW} / {@code A256GCM}).
   */
  String decryptResponse(String jwe);

  /** Public verifier JWKS (signing plus decryption keys). */
  Map<String, Object> jwks();
}
