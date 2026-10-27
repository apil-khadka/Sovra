# `@sovra/policy`

Deterministic authorization guard for AI-proposed evidence plans.

`validatePlan(plan, context)` decides, with no model involvement, whether a
candidate plan may proceed to the holder wallet. Checks run in fixed order:
recommendation gate, shape, issuer trust, RP-selected policy binding,
disclosure budget from that policy alone, citations. Every rejection carries
a stable machine-readable code from `@sovra/shared`. Citations ground the
mapping but can never widen the approved budget.
