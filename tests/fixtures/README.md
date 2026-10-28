# Executable test fixtures

Canonical machine-readable fixtures for the automated test suite. All
identifiers are fictional, all data synthetic, no signatures are real trust
anchors.

- `trust-context.json`: pinned issuer trust set and versioned RP policy used
  by guard tests.
- `trust-context-epoch.json`: the same context plus suspended and expired
  issuers for trust-standing checks.
- `plan-*.json`: candidate plans covering the valid path and each guard
  rejection (unknown issuer, untrusted claim, overbroad disclosure,
  fabricated citation, no-path, unsupported outcome, injection,
  incompatible schema, suspended issuer, expired issuer).

This corpus is frozen alongside the Java guard (SOV-014, NFR-10): the
backend `PlanGuardTests` execute every file, and any change needs the
same review as a guard rule change. The SOV-014 curation history is:
issuer standing fields added to the trust contexts, the no-path plan
gained its policy binding so it parses under the strict schema, and
six files were added for outcome, injection, schema, and epoch cases.

Documentation examples live separately in
`docs/engineering/fixtures/` and are not executed.
