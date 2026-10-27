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

  const nonce = asString(proof["nonce"]);
  if (nonce === null || input.consumedNonces.has(nonce)) {
    return rejected(
      OUTCOME_CODES.VERIFY_REPLAY_DETECTED,
      "Challenge is missing or has already been consumed.",
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
