# Frozen planning evaluation corpus (SOV-013, FR-11, NFR-10)

Version `sovra-planning-corpus/1`: compatible, incompatible, and
adversarial planning cases with the deterministic baseline's expected
recommendation. Content is frozen: changing a case requires renaming
the corpus version in PlanningEvaluationTests, never silent edits. No
country-specific adapter may key off these fixtures; the live agent
must discover mappings through the read-only tools only.

Scoped-discovery live evaluation lives separately in
`../planning-corpus-v2` (`sovra-planning-corpus/2`): different
experiment, different issuers/policies/scopes — results are not
interchangeable with this corpus.
