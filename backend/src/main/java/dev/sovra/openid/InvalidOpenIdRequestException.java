package dev.sovra.openid;

/** Malformed OpenID4VCI/OpenID4VP request envelope (HTTP 400). */
public class InvalidOpenIdRequestException extends RuntimeException {

  public InvalidOpenIdRequestException(String message) {
    super(message);
  }
}
