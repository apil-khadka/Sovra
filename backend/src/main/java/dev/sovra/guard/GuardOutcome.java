package dev.sovra.guard;

/**
 * Stable machine-readable guard outcome codes, ported from the retired
 * TypeScript prototype (`OUTCOME_CODES`) with two additions:
 * {@link #GUARD_UNSUPPORTED_OUTCOME} for claim semantics outside the
 * frozen G1 outcome set, and {@link #GUARD_ISSUER_EPOCH_INVALID} for
 * issuers outside their trusted standing or validity window. Codes are
 * stable across logs, API responses, and UI messages so sanitized
 * reports stay correlatable without identity records.
 */
public enum GuardOutcome {
  GUARD_UNKNOWN_ISSUER,
  GUARD_UNTRUSTED_CREDENTIAL_TYPE,
  GUARD_UNTRUSTED_CLAIM,
  GUARD_OVERBROAD_DISCLOSURE,
  GUARD_MISSING_CITATION,
  GUARD_UNKNOWN_POLICY,
  GUARD_POLICY_MISMATCH,
  GUARD_UNKNOWN_POLICY_SECTION,
  GUARD_MALFORMED_PLAN,
  GUARD_UNSUPPORTED_OUTCOME,
  GUARD_ISSUER_EPOCH_INVALID,
  GUARD_ACCEPTED,
  MANUAL_REVIEW
}
