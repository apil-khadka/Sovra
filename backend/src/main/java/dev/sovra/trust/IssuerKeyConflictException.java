package dev.sovra.trust;

/** Conflicting re-registration of an issuer key identity; mapped to 409. */
public class IssuerKeyConflictException extends RuntimeException {

  public IssuerKeyConflictException() {
    super("issuer key identity names a different key");
  }
}
