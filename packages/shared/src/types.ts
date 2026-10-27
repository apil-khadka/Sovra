/**
 * Shared Sovra contracts.
 *
 * These types mirror the demo orchestration draft
 * (`docs/engineering/api-contract.openapi.yaml`) for the portions this
 * prototype implements. They are design contracts, not claims of official
 * OpenID4VCI/OpenID4VP conformance.
 */

/** Purpose-scoped request submitted by a relying party. */
export interface VerificationIntent {
  relying_party_id: string;
  purpose: string;
  /** Desired proof outcome. Only `age_over_18` is supported in this slice. */
  outcome: "age_over_18";
  policy_id: string;
  policy_version: string;
}

/** Reference to one versioned source section grounding a claimed mapping. */
export interface EvidenceCitation {
  document_id: string;
  section_id: string;
}

/**
 * Candidate evidence mapping proposed by the AI planner.
 * Untrusted until it passes the deterministic guard.
 */
export interface CandidatePlan {
  plan_id: string;
  requested_outcome: string;
  candidate_issuer_id: string;
  credential_type: string;
  claim_paths: string[];
  evidence: EvidenceCitation[];
  /** RP-selected policy binding the disclosure budget; citations cannot widen it. */
  policy_id: string;
  policy_version: string;
  recommendation: "CANDIDATE_ONLY" | "NO_PATH" | "MANUAL_REVIEW";
  /** Optional planner-reported gaps; never a substitute for guard checks. */
  unresolved_issues?: string[];
}

/** Deterministic guard decision over a candidate plan. */
export interface GuardVerdict {
  accepted_for_consideration: boolean;
  /** Machine-readable outcome; see `OUTCOME_CODES`. */
  code: string;
  reason?: string;
}

/** Session created after a plan is approved; binds audience and challenge. */
export interface ProofRequest {
  request_id: string;
  plan_id: string;
  relying_party_id: string;
  audience: string;
  /** Single-use verifier challenge, consumed atomically. */
  nonce: string;
  expires_at: string;
  consent_summary: string;
}

/** Final verification outcome. Never a legal KYC/CDD determination. */
export interface VerificationResult {
  decision: "VERIFIED_EVIDENCE" | "REJECTED" | "MANUAL_REVIEW";
  /** Machine-readable outcome; see `OUTCOME_CODES`. */
  code: string;
  reason_codes: string[];
  issuer_key_reference?: string;
  correlation_id: string;
}

/** Issuer trust metadata pinned for one epoch. */
export interface TrustedIssuer {
  issuer_id: string;
  allowed_credential_types: string[];
  /** Claim names the issuer is trusted to attest, per credential type. */
  allowed_claims: string[];
  key_ids: string[];
}

/** One versioned policy document with addressable sections. */
export interface PolicyDocument {
  document_id: string;
  version: string;
  sections: Record<string, string>;
  /** Claims the relying party may request under this policy version. */
  approved_claims: string[];
}

/** Trust and policy inputs the guard validates a plan against. */
export interface GuardContext {
  trusted_issuers: Record<string, TrustedIssuer>;
  policies: Record<string, PolicyDocument>;
}
