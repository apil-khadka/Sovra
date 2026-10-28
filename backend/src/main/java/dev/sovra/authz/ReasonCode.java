package dev.sovra.authz;

/** Machine-readable authorization outcome; safe to log and return. */
public enum ReasonCode {
  PERMIT,
  ANONYMOUS,
  EMERGENCY_FREEZE,
  CREDENTIAL_REVOKED,
  WRONG_TENANT,
  MISSING_ROLE,
  SELF_APPROVAL
}
