package dev.sovra.kms;

import java.util.UUID;

/**
 * Attested call context (PROD-005). Every production key operation
 * carries who is asking, what binary they run, where they run, and
 * what the key may do — and the provider denies anything that does
 * not match its attestation policy. There is no raw or generic
 * entry: each operation binds its key reference to one purpose, so
 * a signing key can never unwrap and a vault key can never sign.
 *
 * @param tenantId tenant scope for tenant keys; null for platform
 *     keys (issuer signing), which the trust snapshot authorizes
 *     instead
 * @param workload attested workload identity (service account /
 *     SPIFFE ID); must equal the provider's expected value
 * @param imageDigest attested binary digest (supply-chain
 *     binding); must equal the deployed digest
 * @param location attested region/zone; must satisfy the key's
 *     residency policy
 * @param purpose the single allowed purpose (see {@link KmsPurposes});
 *     must equal the key's authorized purpose
 * @param keyRef stable key reference ({@code issuer:keyId:vN} for
 *     signing, {@code tenant:vN} for vault KEKs)
 * @param auditAad canonical call description for the provider's
 *     audit log; authenticated by the transport, not trusted for
 *     authorization
 */
public record KmsCallContext(
    UUID tenantId,
    String workload,
    String imageDigest,
    String location,
    String purpose,
    String keyRef,
    String auditAad) {}
