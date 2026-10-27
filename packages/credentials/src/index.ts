export {
  generateIssuerKeys,
  issueAttestation,
  issueHolderProof,
  verifyAttestationSignature,
} from "./attest.js";
export type {
  AttestationClaims,
  GeneratedIssuerKeys,
  HolderProofInput,
  IssueAttestationInput,
} from "./attest.js";
export type { JWK } from "jose";
