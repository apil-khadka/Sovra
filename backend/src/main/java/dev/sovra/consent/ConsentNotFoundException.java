package dev.sovra.consent;

/** A consent request that is unknown or belongs to another tenant. Maps to an empty 404. */
public class ConsentNotFoundException extends RuntimeException {

  public ConsentNotFoundException() {
    super("consent request not found");
  }
}
