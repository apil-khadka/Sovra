/**
 * Demo-only credential issuance and signature verification.
 *
 * Signs narrowly scoped synthetic attestations (for example,
 * `{ adultOver18: true }`) with a vetted JWT library. This is a labelled
 * demo JWT profile, not an official W3C VC, SD-JWT, or OpenID4VCI flow.
 * Production key custody (HSM/KMS) is out of scope for this slice.
 */

import { CompactSign, compactVerify, exportJWK, generateKeyPair, importJWK } from "jose";
import type { JWK } from "jose";

export interface AttestationClaims {
  /** Narrowly scoped claims only; never a full identity record. */
  [claim: string]: unknown;
}

export interface IssueAttestationInput {
  privateKey: JWK;
  keyId: string;
  issuer: string;
  /** Pseudonymous holder reference, never a real identity. */
  subject: string;
  credentialType: string;
  claims: AttestationClaims;
  issuedAt: Date;
  expiresAt: Date;
  /** Unique credential identifier used for status lookups. */
  credentialId: string;
}

export interface HolderProofInput {
  privateKey: JWK;
  keyId: string;
  /** Pseudonymous holder identifier (decentralized identifier in a real profile). */
  holder: string;
  /** `jti` of the attestation this proof presents. */
  credentialId: string;
  /** Verifier-issued single-use challenge. */
  nonce: string;
  audience: string;
  issuedAt: Date;
  expiresAt: Date;
}

export interface GeneratedIssuerKeys {
  publicKey: JWK;
  privateKey: JWK;
  keyId: string;
}

/** Demo issuer keypair. Dev-only: keys live in memory for tests. */
export async function generateIssuerKeys(keyId: string): Promise<GeneratedIssuerKeys> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const [publicJwk, privateJwk] = await Promise.all([
    exportJWK(publicKey),
    exportJWK(privateKey),
  ]);
  return { publicKey: publicJwk, privateKey: privateJwk, keyId };
}

/** Issue one issuer-signed scoped attestation as a compact JWT. */
export async function issueAttestation(input: IssueAttestationInput): Promise<string> {
  const key = await importJWK(input.privateKey, "EdDSA");
  const payload = {
    iss: input.issuer,
    sub: input.subject,
    jti: input.credentialId,
    type: input.credentialType,
    claims: input.claims,
    iat: Math.floor(input.issuedAt.getTime() / 1000),
    exp: Math.floor(input.expiresAt.getTime() / 1000),
  };
  return new CompactSign(Buffer.from(JSON.stringify(payload)))
    .setProtectedHeader({ alg: "EdDSA", kid: input.keyId, typ: "sovra-attestation+demo" })
    .sign(key);
}

/** Verify compact-JWT integrity and return the decoded payload. */
export async function verifyAttestationSignature(
  token: string,
  publicKey: JWK,
): Promise<Record<string, unknown>> {
  const key = await importJWK(publicKey, "EdDSA");
  const { payload } = await compactVerify(token, key);
  return JSON.parse(Buffer.from(payload).toString("utf8")) as Record<string, unknown>;
}

/**
 * Create a holder proof binding one attestation to a verifier challenge.
 * Demo shape only: a real profile would use a standard holder-binding
 * proof format. The wallet signs this after explicit holder consent.
 */
export async function issueHolderProof(input: HolderProofInput): Promise<string> {
  const key = await importJWK(input.privateKey, "EdDSA");
  const payload = {
    iss: input.holder,
    sub: input.holder,
    bound_jti: input.credentialId,
    nonce: input.nonce,
    aud: input.audience,
    iat: Math.floor(input.issuedAt.getTime() / 1000),
    exp: Math.floor(input.expiresAt.getTime() / 1000),
  };
  return new CompactSign(Buffer.from(JSON.stringify(payload)))
    .setProtectedHeader({ alg: "EdDSA", kid: input.keyId, typ: "sovra-holder-proof+demo" })
    .sign(key);
}
