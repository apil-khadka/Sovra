# Frozen planning evaluation corpus v2 (scoped discovery)

Version `sovra-planning-corpus/2`: five scoped-discovery cases with
data-driven baseline AND live expectations. Every case uses outcome
`age_over_18` with the canonical hint `requestedClaims: ["adultOver18"]`
and FLAT scope arrays (`scopeIssuerIds`, `scopeCredentialTypes`,
`scopeJurisdictions`); the to-be-discovered wire names (`isAdult`,
`qualifiesAsAdult`) never appear in the intent. The scorer binds each
injected candidate to its case intent, scope, expected issuer/type/claims,
and the real guard under the case's RP-selected policy — no `caseId`
branches.

This corpus is a DIFFERENT experiment from `../planning-corpus`
(`sovra-planning-corpus/1`), which stays byte-for-byte frozen. In
particular v1 `U1` names issuer `unseen-fjord-1` with the old
`age-check` policy and `requestedClaims: ["isAdult"]`, while v2
`V2-FJORD` uses issuer `synth-2` with the mapped `age-check-mapped`
policy, hint `["adultOver18"]`, and explicit scope. Results are NOT
interchangeable: never report a v1 pass from v2 injections or vice
versa.

Content is frozen: changing a case requires a new corpus version, never
silent edits. Digests live in `manifest.json`. No fixture-specific
adapter may key off these files; the live agent must discover mappings
through the read-only tools only. Injected/replayed scores never claim
actual provider execution or live generalization; proof execution stays
`NOT_EXECUTED` without separate verification receipts.
