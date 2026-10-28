# Coding agents: safe, parallel implementation playbook

The selected backend is now [Java 25 LTS with Spring](../architecture/java-spring-baseline.md).
The TypeScript prototype was removed; the ownership map below refers to the Java backend (`backend/src/main/java/dev/sovra/`) and the React frontend (`frontend/src/`). Agree the exact module split before delegating work.
Apply the [security validation plan](security-validation-plan.md) to Java implementation and release evidence.
Select work from the [business implementation backlog](implementation-backlog.md), respecting its dependencies and real-data gates.
Agree explicit file/module ownership before any authorized delegated work; contributors must preserve other contributors' changes.

## Principle

Use modern AI coding agents to compress implementation time, **not** to replace architecture governance. Write shared contracts and golden tests before parallel implementation; merge by evidence, not by confidence scores.

## Workstreams

| Stream | Owned paths (suggested) | Contract first | Required independent review |
| --- | --- | --- | --- |
| A Issuance + crypto | `backend/.../issuance`, `backend/.../crypto` | claims/signing/key IDs/status | Credential authority, signatures, algorithm allowlist |
| B RP verification + guard | `backend/.../verification`, `backend/.../guard` | plan validation, challenge protocol, result reasons | Fail closed, atomic replay, trust scope, audience |
| C Meta AI tools | `backend/.../planner` | tool JSON schemas + validation and trace | Prompt injection, permission boundary, API reality |
| D Demo frontend | `frontend/src` | session API, consent/request screen | Don't reveal PII, no fake verification UI |
| E Integration/CI | `tests`, Compose, GitHub Actions | fixture/endpoint contracts and health | New checkout runnable, negative integration suite |

With fewer developers, combine workstreams; do not spawn agents against overlapping files. Maintain one integration owner.

## One-task agent brief format

```text
Context: Sovra Java business implementation. Read docs/README.md,
docs/requirements/software-requirements-specification.md,
docs/architecture/security-privacy-threat-model.md, the assigned backlog task,
and the relevant versioned API/proof contract.
Task: [SOV ID and single bounded feature].
Ownership: [allowed paths].
Coordination: you are not alone; preserve others' edits and accommodate their changes.
Dependencies and gate: [accepted prerequisites and evidence scope].
Non-goals: no scope expansion, no real PII, no custom crypto, no fake standards claims.
Acceptance: [tests to pass, expected responses, failure cases].
Provide: diff, commands executed, test evidence, assumptions, unresolved issues.
Never add .intel, keys, secrets, model outputs containing credentials to Git.
```

## Merge gates

- Tests fail before a behavior fix and pass after it; not only generated happy-path tests.
- Java builds pin the Maven wrapper, Boot/AI BOMs, plugins, and effective dependency versions; the frontend keeps its `pnpm` lockfile pinned.
- Dependency maintenance, licenses, provenance, and vulnerabilities reviewed for both build systems.
- Secret scan + denylist for `.intel` and real identity data.
- Data never goes directly from model-generated text into network requests without typed tool dispatcher/allowlist.
- End-to-end fresh checkout and Docker Compose work without undocumented manual steps.
- Review observed Meta model invocation and separate guard results.

## Operational cadence

Use the [repository triage workflow](repository-workflow.md) with named owners, one status label and evidence before closure.
Keep changes small and the accepted baseline reproducible; test affected security boundaries with every component change.
The [dated hackathon schedule](hackathon-milestone-plan.md) governs the synthetic milestone only.
Business security and real-data gates remain mandatory regardless of milestone dates.
