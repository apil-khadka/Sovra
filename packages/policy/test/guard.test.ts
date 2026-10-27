import { describe, expect, it } from "vitest";
import { OUTCOME_CODES, type CandidatePlan, type GuardContext } from "@sovra/shared";
import { validatePlan } from "../src/guard.js";
import { loadFixture } from "./fixtures.js";

const context = loadFixture<GuardContext>("trust-context.json");
const planValid = loadFixture<CandidatePlan>("plan-valid.json");
const planUnknownIssuer = loadFixture<CandidatePlan>("plan-unknown-issuer.json");
const planOverbroad = loadFixture<CandidatePlan>("plan-overbroad.json");
const planUntrustedClaim = loadFixture<CandidatePlan>("plan-untrusted-claim.json");
const planFabricatedCitation = loadFixture<CandidatePlan>("plan-fabricated-citation.json");
const planNoPath = loadFixture<CandidatePlan>("plan-no-path.json");

describe("validatePlan", () => {
  it("accepts a trusted, minimal, cited plan", () => {
    const verdict = validatePlan(planValid, context);
    expect(verdict.accepted_for_consideration).toBe(true);
    expect(verdict.code).toBe(OUTCOME_CODES.GUARD_ACCEPTED);
  });

  it("rejects an invented issuer before the wallet is involved", () => {
    const verdict = validatePlan(planUnknownIssuer, context);
    expect(verdict.accepted_for_consideration).toBe(false);
    expect(verdict.code).toBe(OUTCOME_CODES.GUARD_UNKNOWN_ISSUER);
  });

  it("rejects a claim outside the issuer's trusted scope", () => {
    const verdict = validatePlan(planUntrustedClaim, context);
    expect(verdict.accepted_for_consideration).toBe(false);
    expect(verdict.code).toBe(OUTCOME_CODES.GUARD_UNTRUSTED_CLAIM);
  });

  it("rejects an in-scope claim that exceeds the RP disclosure budget", () => {
    const verdict = validatePlan(planOverbroad, context);
    expect(verdict.accepted_for_consideration).toBe(false);
    expect(verdict.code).toBe(OUTCOME_CODES.GUARD_OVERBROAD_DISCLOSURE);
  });

  it("rejects a fabricated policy section citation", () => {
    const verdict = validatePlan(planFabricatedCitation, context);
    expect(verdict.accepted_for_consideration).toBe(false);
    expect(verdict.code).toBe(OUTCOME_CODES.GUARD_UNKNOWN_POLICY_SECTION);
  });

  it("routes an explicit no-path plan to manual review, not the wallet", () => {
    const verdict = validatePlan(planNoPath, context);
    expect(verdict.accepted_for_consideration).toBe(false);
    expect(verdict.code).toBe(OUTCOME_CODES.MANUAL_REVIEW);
  });

  it("rejects a plan bound to an unknown policy version", () => {
    const verdict = validatePlan({ ...planValid, policy_version: "99" }, context);
    expect(verdict.accepted_for_consideration).toBe(false);
    expect(verdict.code).toBe(OUTCOME_CODES.GUARD_UNKNOWN_POLICY);
  });

  it("rejects a malformed plan missing required fields", () => {
    const malformed: CandidatePlan = { ...planValid, claim_paths: [] };
    const verdict = validatePlan(malformed, context);
    expect(verdict.accepted_for_consideration).toBe(false);
    expect(verdict.code).toBe(OUTCOME_CODES.GUARD_MALFORMED_PLAN);
  });
});
