package dev.sovra.issuance;

/**
 * Encodes validated issuance evidence into a signed artifact. G1 ships
 * the synthetic JWT below; the walt-id SD-JWT VC encoder replaces it
 * behind this interface once SOV-036 passes (SOV-001 section 3).
 */
public interface CredentialEncoder {

  EncodedCredential encode(IssuanceEvidence evidence);

  record EncodedCredential(String artifact, String claimsJson) {}
}
