# Executable test fixtures

Canonical machine-readable fixtures for the automated test suite. All
identifiers are fictional, all data synthetic, no signatures are real trust
anchors.

- `trust-context.json`: pinned issuer trust set and versioned RP policy used
  by guard tests.
- `plan-*.json`: candidate plans covering the valid path and each guard
  rejection (unknown issuer, untrusted claim, overbroad disclosure,
  fabricated citation, no-path).

Documentation examples live separately in
`docs/engineering/fixtures/` and are not executed.
