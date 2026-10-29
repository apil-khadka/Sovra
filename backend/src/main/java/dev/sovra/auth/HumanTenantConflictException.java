package dev.sovra.auth;

/**
 * Membership login attempted from a different tenant than the one the
 * {@code (issuer, subject)} pair is pinned to. Human memberships never
 * migrate tenants implicitly: the first login pins the tenant, and a
 * later login carrying another tenant is denied, never re-homed.
 */
public class HumanTenantConflictException extends RuntimeException {

  public HumanTenantConflictException() {
    super("membership belongs to another tenant");
  }
}
