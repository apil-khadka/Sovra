import { describe, expect, it } from "vitest";
import { OUTCOME_CODES } from "@sovra/shared";
import {
  generateIssuerKeys,
  issueAttestation,
  issueHolderProof,
} from "@sovra/credentials";
import { createChallenge, verifyPresentation, type PresentationTrust } from "../src/verify.js";

const now = new Date("2026-10-27T12:00:00Z");
const issuedAt = new Date("2026-10-27T11:00:00Z");
const expiresAt = new Date("2026-10-27T13:00:00Z");

async function happyPath(status: "ACTIVE" | "REVOKED" | "UNKNOWN" = "ACTIVE") {
  const issuer = await generateIssuerKeys("np-demo-ed25519-v1");
  const holder = await generateIssuerKeys("holder-key-001");
  const consumedNonces = new Set<string>();
  const challenge = createChallenge({
    relyingPartyId: "rp-au-demo",
    audience: "rp-au-demo",
    consentSummary: "age_over_18 to rp-au-demo",
    ttlSeconds: 300,
    now,
  });
  const attestation = await issueAttestation({
    privateKey: issuer.privateKey,
    keyId: issuer.keyId,
    issuer: "np-synthetic-issuer",
    subject: "holder-pseudonym-001",
    credentialType: "AdultStatusCredential",
    claims: { adultOver18: true },
    issuedAt,
    expiresAt,
    credentialId: "cred-001",
  });
  const holderProof = await issueHolderProof({
    privateKey: holder.privateKey,
    keyId: holder.keyId,
    holder: "holder-pseudonym-001",
    credentialId: "cred-001",
    nonce: challenge.nonce,
    audience: "rp-au-demo",
    issuedAt,
    expiresAt,
  });
  const trust: PresentationTrust = {
    trustedIssuers: { "np-synthetic-issuer": { keyIds: ["np-demo-ed25519-v1"] } },
    issuerKeys: { "np-demo-ed25519-v1": issuer.publicKey },
    holderKeys: { "holder-pseudonym-001": holder.publicKey },
    statusOf: () => status,
  };
  const input = {
    attestation,
    holderProof,
    expectedAudience: "rp-au-demo",
    consumedNonces,
    consentGranted: true,
    correlationId: "corr-001",
    now,
  };
  return { input, trust, consumedNonces, issuer };
}

describe("verifyPresentation", () => {
  it("accepts a valid consented presentation and consumes the challenge", async () => {
    const { input, trust, consumedNonces } = await happyPath();
    const result = await verifyPresentation(input, trust);
    expect(result.decision).toBe("VERIFIED_EVIDENCE");
    expect(result.code).toBe(OUTCOME_CODES.VERIFIED_EVIDENCE);
    expect(consumedNonces.size).toBe(1);
  });

  it("rejects a replayed challenge", async () => {
    const { input, trust } = await happyPath();
    const first = await verifyPresentation(input, trust);
    expect(first.decision).toBe("VERIFIED_EVIDENCE");
    const second = await verifyPresentation(input, trust);
    expect(second.decision).toBe("REJECTED");
    expect(second.code).toBe(OUTCOME_CODES.VERIFY_REPLAY_DETECTED);
  });

  it("rejects the wrong audience", async () => {
    const { input, trust } = await happyPath();
    const result = await verifyPresentation(
      { ...input, expectedAudience: "rp-other" },
      trust,
    );
    expect(result.code).toBe(OUTCOME_CODES.VERIFY_AUDIENCE_MISMATCH);
  });

  it("rejects a revoked credential", async () => {
    const { input, trust } = await happyPath("REVOKED");
    const result = await verifyPresentation(input, trust);
    expect(result.code).toBe(OUTCOME_CODES.VERIFY_REVOKED);
  });

  it("fails closed on unknown status", async () => {
    const { input, trust } = await happyPath("UNKNOWN");
    const result = await verifyPresentation(input, trust);
    expect(result.decision).toBe("REJECTED");
    expect(result.code).toBe(OUTCOME_CODES.VERIFY_STATUS_UNKNOWN);
  });

  it("rejects a tampered attestation", async () => {
    const { input, trust } = await happyPath();
    const [header, , signature] = input.attestation.split(".");
    const forged = Buffer.from(JSON.stringify({ iss: "np-synthetic-issuer" })).toString(
      "base64url",
    );
    const result = await verifyPresentation(
      { ...input, attestation: `${header}.${forged}.${signature}` },
      trust,
    );
    expect(result.code).toBe(OUTCOME_CODES.VERIFY_INVALID_SIGNATURE);
  });

  it("rejects an attestation from an unknown issuer", async () => {
    const { input, trust } = await happyPath();
    const rogue = await generateIssuerKeys("rogue-key-001");
    const rogueAttestation = await issueAttestation({
      privateKey: rogue.privateKey,
      keyId: rogue.keyId,
      issuer: "rogue-issuer",
      subject: "holder-pseudonym-001",
      credentialType: "AdultStatusCredential",
      claims: { adultOver18: true },
      issuedAt,
      expiresAt,
      credentialId: "cred-rogue",
    });
    const result = await verifyPresentation(
      { ...input, attestation: rogueAttestation },
      trust,
    );
    expect(result.code).toBe(OUTCOME_CODES.VERIFY_UNTRUSTED_ISSUER);
  });

  it("rejects an expired presentation", async () => {
    const { input, trust } = await happyPath();
    const result = await verifyPresentation(
      { ...input, now: new Date("2026-10-28T00:00:00Z") },
      trust,
    );
    expect(result.code).toBe(OUTCOME_CODES.VERIFY_EXPIRED);
  });

  it("rejects without holder consent and sends no proof outcome", async () => {
    const { input, trust, consumedNonces } = await happyPath();
    const result = await verifyPresentation({ ...input, consentGranted: false }, trust);
    expect(result.code).toBe(OUTCOME_CODES.VERIFY_CONSENT_DENIED);
    expect(consumedNonces.size).toBe(0);
  });
});
