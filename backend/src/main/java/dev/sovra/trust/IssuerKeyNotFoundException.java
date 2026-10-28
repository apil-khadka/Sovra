package dev.sovra.trust;

/** Unknown issuer key identity; mapped to an empty 404. */
public class IssuerKeyNotFoundException extends RuntimeException {

  public IssuerKeyNotFoundException() {
    super("issuer key is unknown");
  }
}
