package dev.sovra.issuance;

/**
 * Encodes validated issuance evidence into a signed artifact. Two
 * profiles live behind this interface: the synthetic JWT
 * (default) and the walt-id SD-JWT VC encoder, selected by
 * {@code sovra.profile=sdjwt-vc} (SOV-001 section 3, SOV-036).
 */
public interface CredentialEncoder {

  EncodedCredential encode(IssuanceEvidence evidence);

  record EncodedCredential(String artifact) {}
}
