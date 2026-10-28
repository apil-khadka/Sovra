package dev.sovra.tenancy;

/** Thrown when tenant-scoped access runs without an authenticated context. */
public class TenantRequiredException extends RuntimeException {

  public TenantRequiredException(String message) {
    super(message);
  }
}
