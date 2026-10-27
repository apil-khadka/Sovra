# `@sovra/verifier`

Deterministic verification of consented demo presentations.

Checks one presentation — an issuer-signed attestation plus a holder-signed
challenge binding — in fixed order: consent, attestation signature and
trust, holder-proof signature and binding, expiry, audience, single-use
challenge consumption, and credential status. Unknown status fails closed.
A valid signature establishes control of a key, never government authority
or legal KYC sufficiency.
