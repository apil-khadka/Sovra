package dev.sovra.authz;

/** Closed set of authorizable actions. Unknown actions cannot exist. */
public enum Action {
  ISSUE_CREDENTIAL,
  READ_CREDENTIAL,
  PROPOSE_TRUST_CHANGE,
  APPROVE_TRUST_CHANGE,
  ACTIVATE_TRUST_SNAPSHOT,
  READ_AUDIT,
  REQUEST_PROOF,
  READ_CONSENT,
  DECIDE_CONSENT
}
