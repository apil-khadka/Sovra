package dev.sovra.auth;

/** Closed accreditation lifecycle states mirrored by V37's database check. */
public enum AccreditationState {
  REQUESTED,
  APPROVED,
  REJECTED,
  REVOKED
}
