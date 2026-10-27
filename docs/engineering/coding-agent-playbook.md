# Coding agents: safe, parallel implementation playbook

## Principle

Use modern AI coding agents to compress implementation time, **not** to replace architecture governance. Write shared contracts and golden tests before parallel implementation; merge by evidence, not by confidence scores.

## Workstreams

| Stream | Owned paths (suggested) | Contract first | Required independent review |
| --- | --- | --- | --- |
| A Issuance + crypto | `packages/credentials`, `apps/country-node` | claims/signing/key IDs/status | Credential authority, signatures, algorithm allowlist |
| B RP verification + guard | `packages/policy`, `apps/verifier` | plan validation, challenge protocol, result reasons | Fail closed, atomic replay, trust scope, audience |
| C Meta AI tools | `packages/ai`, `apps/agent` | tool JSON schemas + validation and trace | Prompt injection, permission boundary, API reality |
| D Demo frontend | `apps/web` | session API, consent/request screen | Don't reveal PII, no fake verification UI |
| E Integration/CI | `tests`, Compose, GitHub Actions | fixture/endpoint contracts and health | New checkout runnable, negative integration suite |

With fewer developers, combine workstreams; do not spawn agents against overlapping files. Maintain one integration owner.

## One-task agent brief format

```text
Context: TrustMesh, Oct 27–Nov 4 hackathon. Read docs/README.md,
requirements/software-requirements-specification.md,
architecture/security-privacy-threat-model.md, and the assigned contract.
Task: [single bounded feature].
Ownership: [allowed paths].
Non-goals: no scope expansion, no real PII, no custom crypto, no fake standards claims.
Acceptance: [tests to pass, expected responses, failure cases].
Provide: diff, commands executed, test evidence, assumptions, unresolved issues.
Never add .intel, keys, secrets, model outputs containing credentials to Git.
```

## Merge gates

- Tests fail before a behavior fix and pass after it; not only generated happy-path tests.
- `npm`/`pnpm` lockfile pinned; dependency licenses and vulnerabilities reviewed.
- Secret scan + denylist for `.intel` and real identity data.
- Data never goes directly from model-generated text into network requests without typed tool dispatcher/allowlist.
- End-to-end fresh checkout and Docker Compose work without undocumented manual steps.
- Review observed Meta model invocation and separate guard results.

## Operational cadence

Maintain a small issue board with `todo`, `implementing`, `tests`, `review`, `merged`, `blocked`. Each day end with a working main branch and runnable smoke flow. Freeze functionality by November 3.
