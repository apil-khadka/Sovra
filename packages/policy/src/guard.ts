/**
 * Deterministic authorization guard.
 *
 * A candidate plan proposed by the AI planner is untrusted input. This guard
 * decides, with no model involvement, whether the plan may proceed to the
 * holder wallet. Every rejection carries a stable machine-readable code.
 *
 * Validation order is fixed so failures are deterministic:
 * shape, issuer trust, credential scope, disclosure budget, citations.
 */

import {
  OUTCOME_CODES,
  type CandidatePlan,
  type GuardContext,
  type GuardVerdict,
  type TrustedIssuer,
} from "@sovra/shared";

function reject(code: string, reason: string): GuardVerdict {
  return { accepted_for_consideration: false, code, reason };
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function checkShape(plan: CandidatePlan): GuardVerdict | null {
  if (
    !isNonEmptyString(plan.plan_id) ||
    !isNonEmptyString(plan.requested_outcome) ||
    !isNonEmptyString(plan.candidate_issuer_id) ||
    !isNonEmptyString(plan.credential_type) ||
    !isNonEmptyString(plan.policy_id) ||
    !isNonEmptyString(plan.policy_version) ||
    !Array.isArray(plan.claim_paths) ||
    plan.claim_paths.length === 0 ||
    !plan.claim_paths.every(isNonEmptyString) ||
    !Array.isArray(plan.evidence)
  ) {
    return reject(
      OUTCOME_CODES.GUARD_MALFORMED_PLAN,
      "Plan is missing required fields or carries empty claim paths.",
    );
  }
  for (const citation of plan.evidence) {
    if (!isNonEmptyString(citation?.document_id) || !isNonEmptyString(citation?.section_id)) {
      return reject(
        OUTCOME_CODES.GUARD_MISSING_CITATION,
        "Every claimed mapping must cite a document and section.",
      );
    }
  }
  return null;
}

function checkIssuer(
  plan: CandidatePlan,
  context: GuardContext,
): GuardVerdict | TrustedIssuer {
  const issuer = context.trusted_issuers[plan.candidate_issuer_id];
  if (!issuer) {
    return reject(
      OUTCOME_CODES.GUARD_UNKNOWN_ISSUER,
      `Issuer '${plan.candidate_issuer_id}' is not in the pinned trust set.`,
    );
  }
  if (!issuer.allowed_credential_types.includes(plan.credential_type)) {
    return reject(
      OUTCOME_CODES.GUARD_UNTRUSTED_CREDENTIAL_TYPE,
      `Credential type '${plan.credential_type}' is outside issuer scope.`,
    );
  }
  return issuer;
}

function checkDisclosureBudget(
  plan: CandidatePlan,
  issuer: TrustedIssuer,
  policyClaims: string[],
): GuardVerdict | null {
  for (const claim of plan.claim_paths) {
    if (!issuer.allowed_claims.includes(claim)) {
      return reject(
        OUTCOME_CODES.GUARD_UNTRUSTED_CLAIM,
        `Claim '${claim}' is outside the issuer's trusted attestation scope.`,
      );
    }
    if (!policyClaims.includes(claim)) {
      return reject(
        OUTCOME_CODES.GUARD_OVERBROAD_DISCLOSURE,
        `Claim '${claim}' exceeds the relying party's approved disclosure budget.`,
      );
    }
  }
  return null;
}

function checkCitations(plan: CandidatePlan, context: GuardContext): GuardVerdict | null {
  if (plan.evidence.length === 0) {
    return reject(
      OUTCOME_CODES.GUARD_MISSING_CITATION,
      "Plan carries no source citations for its claimed mapping.",
    );
  }
  for (const citation of plan.evidence) {
    const policy = context.policies[citation.document_id];
    if (!policy) {
      return reject(
        OUTCOME_CODES.GUARD_UNKNOWN_POLICY,
        `Cited policy '${citation.document_id}' is not a known versioned document.`,
      );
    }
    if (!(citation.section_id in policy.sections)) {
      return reject(
        OUTCOME_CODES.GUARD_UNKNOWN_POLICY_SECTION,
        `Section '${citation.section_id}' does not exist in '${citation.document_id}'.`,
      );
    }
  }
  return null;
}

/**
 * Validate a candidate plan against pinned trust and policy.
 * Returns `GUARD_ACCEPTED` only when every check passes; the wallet must
 * still obtain explicit holder consent before any presentation.
 */
export interface SelectedPolicy {
  policy_id: string;
  policy_version: string;
}

export function validatePlan(
  plan: CandidatePlan,
  context: GuardContext,
  selected: SelectedPolicy,
): GuardVerdict {
  if (plan.recommendation !== "CANDIDATE_ONLY") {
    return {
      accepted_for_consideration: false,
      code: OUTCOME_CODES.MANUAL_REVIEW,
      reason: "Planner reports no executable path; a human must review.",
    };
  }

  const shape = checkShape(plan);
  if (shape) return shape;

  const issuer = checkIssuer(plan, context);
  if (!("issuer_id" in issuer)) return issuer;

  // The disclosure budget comes only from the RP-selected policy, delivered
  // through trusted input alongside the plan. The plan echoes its policy
  // binding, but a mismatch with the trusted selection is a rejection:
  // citations and self-selected policies can never widen what the RP approved.
  if (
    plan.policy_id !== selected.policy_id ||
    plan.policy_version !== selected.policy_version
  ) {
    return reject(
      OUTCOME_CODES.GUARD_POLICY_MISMATCH,
      `Plan policy '${plan.policy_id}' version '${plan.policy_version}' does not match the RP-selected policy.`,
    );
  }
  const trusted = context.policies[selected.policy_id];
  if (!trusted || trusted.version !== selected.policy_version) {
    return reject(
      OUTCOME_CODES.GUARD_UNKNOWN_POLICY,
      `Selected policy '${selected.policy_id}' version '${selected.policy_version}' is not a known versioned policy.`,
    );
  }

  const budget = checkDisclosureBudget(plan, issuer, trusted.approved_claims);
  if (budget) return budget;

  const citations = checkCitations(plan, context);
  if (citations) return citations;

  return { accepted_for_consideration: true, code: OUTCOME_CODES.GUARD_ACCEPTED };
}
