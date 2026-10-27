import { describe, expect, it } from "vitest";
import {
  generateIssuerKeys,
  issueAttestation,
  issueHolderProof,
  verifyAttestationSignature,
} from "../src/attest.js";

const issuedAt = new Date("2026-10-27T00:00:00Z");
const expiresAt = new Date("2026-10-28T00:00:00Z");

describe("demo attestations", () => {
  it("round-trips an issuer-signed scoped attestation", async () => {
    const keys = await generateIssuerKeys("np-demo-ed25519-v1");
    const token = await issueAttestation({
      privateKey: keys.privateKey,
      keyId: keys.keyId,
      issuer: "np-synthetic-issuer",
      subject: "holder-pseudonym-001",
      credentialType: "AdultStatusCredential",
      claims: { adultOver18: true },
      issuedAt,
      expiresAt,
      credentialId: "cred-001",
    });
    const payload = await verifyAttestationSignature(token, keys.publicKey);
    expect(payload["iss"]).toBe("np-synthetic-issuer");
    expect(payload["jti"]).toBe("cred-001");
    expect(payload["claims"]).toEqual({ adultOver18: true });
  });

  it("fails verification for a tampered payload", async () => {
    const keys = await generateIssuerKeys("np-demo-ed25519-v1");
    const token = await issueAttestation({
      privateKey: keys.privateKey,
      keyId: keys.keyId,
      issuer: "np-synthetic-issuer",
      subject: "holder-pseudonym-001",
      credentialType: "AdultStatusCredential",
      claims: { adultOver18: true },
      issuedAt,
      expiresAt,
      credentialId: "cred-001",
    });
    const [header, , signature] = token.split(".");
    const forgedPayload = Buffer.from(
      JSON.stringify({ iss: "np-synthetic-issuer", claims: { adultOver18: false } }),
    ).toString("base64url");
    await expect(
      verifyAttestationSignature(`${header}.${forgedPayload}.${signature}`, keys.publicKey),
    ).rejects.toThrow();
  });

  it("fails verification under a substituted issuer key", async () => {
    const issuer = await generateIssuerKeys("np-demo-ed25519-v1");
    const attacker = await generateIssuerKeys("np-demo-ed25519-v1");
    const token = await issueAttestation({
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
    await expect(verifyAttestationSignature(token, attacker.publicKey)).rejects.toThrow();
  });

  it("binds a holder proof to one attestation and challenge", async () => {
    const holder = await generateIssuerKeys("holder-key-001");
    const proof = await issueHolderProof({
      privateKey: holder.privateKey,
      keyId: holder.keyId,
      holder: "holder-pseudonym-001",
      credentialId: "cred-001",
      nonce: "nonce-abc",
      audience: "rp-au-demo",
      issuedAt,
      expiresAt,
    });
    const payload = await verifyAttestationSignature(proof, holder.publicKey);
    expect(payload["bound_jti"]).toBe("cred-001");
    expect(payload["nonce"]).toBe("nonce-abc");
    expect(payload["aud"]).toBe("rp-au-demo");
  });
});
