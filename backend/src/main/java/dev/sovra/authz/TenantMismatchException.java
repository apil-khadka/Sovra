package dev.sovra.authz;

/**
 * Caller reached across a tenant boundary. Rendered as HTTP 404 with an
 * empty body so responses never confirm or deny another tenant's objects.
 */
public class TenantMismatchException extends RuntimeException {

  public TenantMismatchException() {
    super("not found");
  }
}
