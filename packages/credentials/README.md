# `@sovra/credentials`

Demo-only issuance and signature checks for synthetic scoped attestations.

Signs narrowly scoped synthetic claims (for example `{ adultOver18: true }`)
as compact JWTs with the vetted `jose` library, and creates holder proofs
that bind one attestation to a verifier challenge. This is a labelled demo
JWT profile, not an official W3C VC, SD-JWT, or OpenID4VCI flow. Production
key custody (HSM/KMS) is out of scope.
