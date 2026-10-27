/**
 * Deterministic verification of consented demo presentations.
 *
 * A presentation is an issuer-signed attestation plus a holder-signed proof
 * binding that attestation to one verifier challenge. Checks run in fixed
 * order: consent, attestation signature and trust, holder-proof signature
 * and binding, expiry, audience, single-use challenge consumption, and
 * credential status. Unknown status fails closed. A valid signature
 * establishes control of a key, never government authority or legal KYC
 * sufficiency.
 */

import { randomUUID } from "node:crypto";
import { OUTCOME_CODES, type VerificationResult } from "@sovra/shared";
import { verifyAttestationSignature, type JWK } from "@sovra/credentials";

export type CredentialStatus = "ACTIVE" | "REVOKED" | "UNKNOWN";

export interface PresentationTrust {
  trustedIssuers: Record<string, { keyIds: string[] }>;
  /** Pinned issuer public keys by key ID; only these may verify. */
  issuerKeys: Record<string, JWK>;
  holderKeys: Record<string, JWK>;
  statusOf: (credentialId: string) => CredentialStatus;
}

export interface PresentationInput {
  /** Issuer-signed scoped attestation (compact JWT). */
  attestation: string;
  /** Holder-signed challenge binding (compact JWT). */
  holderProof: string;
  expectedAudience: string;
  /** Challenge this verifier issued for this session; holder input is untrusted. */
  expectedNonce: string;
  challengeExpiresAt: Date;
  /** Credential type and claim values the approved plan requires. */
  expectedCredentialType: string;
  requiredClaims: Record<string, unknown>;
  /** Single-use challenges already consumed; extended only on success. */
  consumedNonces: Set<string>;
  consentGranted: boolean;
  correlationId: string;
  now?: Date;
}

export interface SessionInput {
  relyingPartyId: string;
  audience: string;
  consentSummary: string;
  ttlSeconds: number;
  now?: Date;
}

function rejected(code: string, reason: string, correlationId: string): VerificationResult {
  return { decision: "REJECTED", code, reason_codes: [reason], correlation_id: correlationId };
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function asInteger(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

function claimEquals(actual: unknown, required: unknown): boolean {
  if (Object.is(actual, required)) return true;
  if (
    typeof actual === "object" &&
    typeof required === "object" &&
    actual !== null &&
    required !== null
  ) {
    return JSON.stringify(actual) === JSON.stringify(required);
  }
  return false;
}

function headerKeyId(token: string): string {
  try {
    const header = JSON.parse(
      Buffer.from(token.split(".")[0] ?? "", "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    return typeof header["kid"] === "string" ? header["kid"] : "";
  } catch {
    return "";
  }
}

function payloadPreview(token: string): Record<string, unknown> | null {
  try {
    return JSON.parse(
      Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"),
    ) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Create a verifier-issued challenge bound to one audience and lifetime. */
export function createChallenge(input: SessionInput): {
  nonce: string;
  audience: string;
  expiresAt: Date;
  requestId: string;
} {
  const now = input.now ?? new Date();
  return {
    nonce: randomUUID(),
    audience: input.audience,
    expiresAt: new Date(now.getTime() + input.ttlSeconds * 1000),
    requestId: randomUUID(),
  };
}

/** Verify one consented presentation against pinned trust and live status. */
export async function verifyPresentation(
  input: PresentationInput,
  trust: PresentationTrust,
): Promise<VerificationResult> {
  if (!input.consentGranted) {
    return rejected(
      OUTCOME_CODES.VERIFY_CONSENT_DENIED,
      "Holder consent is required before verification.",
      input.correlationId,
    );
  }

  const attestationPreview = payloadPreview(input.attestation);
  const issuer = attestationPreview ? asString(attestationPreview["iss"]) : null;
  const issuerRecord = issuer ? trust.trustedIssuers[issuer] : undefined;
  const keyId = headerKeyId(input.attestation);
  const issuerKey = trust.issuerKeys[keyId];
  if (!issuerRecord || !issuerKey || !issuerRecord.keyIds.includes(keyId)) {
    return rejected(
      OUTCOME_CODES.VERIFY_UNTRUSTED_ISSUER,
      "Issuer or signing key is outside the pinned trust set.",
      input.correlationId,
    );
  }

  let attestation: Record<string, unknown>;
  try {
    attestation = await verifyAttestationSignature(input.attestation, issuerKey);
  } catch {
    return rejected(
      OUTCOME_CODES.VERIFY_INVALID_SIGNATURE,
      "Attestation signature is invalid or malformed.",
      input.correlationId,
    );
  }

  const credentialId = asString(attestation["jti"]);
  const holderPreview = payloadPreview(input.holderProof);
  const holder = holderPreview ? asString(holderPreview["iss"]) : null;
  const holderKey = holder ? trust.holderKeys[holder] : undefined;
  if (!holderKey) {
    return rejected(
      OUTCOME_CODES.VERIFY_INVALID_SIGNATURE,
      "Holder proof comes from an unknown holder key.",
      input.correlationId,
    );
  }

  let proof: Record<string, unknown>;
  try {
    proof = await verifyAttestationSignature(input.holderProof, holderKey);
  } catch {
    return rejected(
      OUTCOME_CODES.VERIFY_INVALID_SIGNATURE,
      "Holder proof signature is invalid or malformed.",
      input.correlationId,
    );
  }

  if (credentialId === null || proof["bound_jti"] !== credentialId) {
    return rejected(
      OUTCOME_CODES.VERIFY_INVALID_SIGNATURE,
      "Holder proof is not bound to the presented attestation.",
      input.correlationId,
    );
  }

  // The presenter must be the subject the issuer attested about; any other
  // registered holder presenting this credential is rejected here.
  if (proof["iss"] !== attestation["sub"]) {
    return rejected(
      OUTCOME_CODES.VERIFY_INVALID_SIGNATURE,
      "Holder proof presenter does not match the attestation subject.",
      input.correlationId,
    );
  }

  // Verification never upgrades evidence: the credential must be the
  // approved type and must carry each required claim value.
  if (attestation["type"] !== input.expectedCredentialType) {
    return rejected(
      OUTCOME_CODES.VERIFY_CREDENTIAL_MISMATCH,
      "Attestation is not the approved credential type.",
      input.correlationId,
    );
  }
  const attestationClaims =
    typeof attestation["claims"] === "object" && attestation["claims"] !== null
      ? (attestation["claims"] as Record<string, unknown>)
      : {};
  for (const [claim, required] of Object.entries(input.requiredClaims)) {
    if (!claimEquals(attestationClaims[claim], required)) {
      return rejected(
        OUTCOME_CODES.VERIFY_CREDENTIAL_MISMATCH,
        `Attestation does not meet required claim '${claim}'.`,
        input.correlationId,
      );
    }
  }

  const nowSeconds = Math.floor((input.now ?? new Date()).getTime() / 1000);
  const attestationExpiry = asInteger(attestation["exp"]);
  const proofExpiry = asInteger(proof["exp"]);
  if (
    attestationExpiry === null ||
    proofExpiry === null ||
    attestationExpiry <= nowSeconds ||
    proofExpiry <= nowSeconds
  ) {
    return rejected(
      OUTCOME_CODES.VERIFY_EXPIRED,
      "Attestation or holder proof has expired.",
      input.correlationId,
    );
  }

  if (proof["aud"] !== input.expectedAudience) {
    return rejected(
      OUTCOME_CODES.VERIFY_AUDIENCE_MISMATCH,
      "Holder proof audience does not match this verifier.",
      input.correlationId,
    );
  }

  // Only a challenge this verifier issued for this session is acceptable;
  // holder-invented nonces and expired challenges are rejected.
  const nonce = asString(proof["nonce"]);
  if (nonce === null || nonce !== input.expectedNonce) {
    return rejected(
      OUTCOME_CODES.VERIFY_REPLAY_DETECTED,
      "Challenge was not issued by this verifier for this session.",
      input.correlationId,
    );
  }
  if (input.challengeExpiresAt.getTime() <= (input.now ?? new Date()).getTime()) {
    return rejected(
      OUTCOME_CODES.VERIFY_EXPIRED,
      "Verifier challenge has expired.",
      input.correlationId,
    );
  }
  if (input.consumedNonces.has(nonce)) {
    return rejected(
      OUTCOME_CODES.VERIFY_REPLAY_DETECTED,
      "Challenge has already been consumed.",
      input.correlationId,
    );
  }

  const status = credentialId ? trust.statusOf(credentialId) : "UNKNOWN";
  if (status !== "ACTIVE") {
    return rejected(
      status === "REVOKED" ? OUTCOME_CODES.VERIFY_REVOKED : OUTCOME_CODES.VERIFY_STATUS_UNKNOWN,
      status === "REVOKED"
        ? "Credential has been revoked."
        : "Credential status is unknown; failing closed.",
      input.correlationId,
    );
  }

  input.consumedNonces.add(nonce);
  return {
    decision: "VERIFIED_EVIDENCE",
    code: OUTCOME_CODES.VERIFIED_EVIDENCE,
    reason_codes: ["Signature, trust, status, audience, and challenge checks passed."],
    issuer_key_reference: `${issuer ?? "unknown"}:${headerKeyId(input.attestation)}`,
    correlation_id: input.correlationId,
  };
}
