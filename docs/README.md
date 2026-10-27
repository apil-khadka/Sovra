# Sovra - Documentation Index

**Snapshot:** 2026-10-27 · **Status:** proposed hackathon architecture; not a production identity system.

Sovra explores whether a **Meta-powered, policy-grounded interoperability planner** can discover compatible verification evidence across independently governed identity systems, while keeping user identity source records in local jurisdiction-controlled domains.
It is a research/demo prototype using **synthetic data** and **simulated jurisdictions**.

> **Design contract:** Meta AI proposes. Approved policies, consent and deterministic code authorize. Issuers sign evidence. Verifiers verify evidence. Relying parties decide legal KYC/CDD sufficiency themselves.

## Reading map

| Question | Document |
| --- | --- |
| Why does Sovra exist, and what is new? | [Vision](product/vision-and-scope.md), [Positioning](product/positioning-and-alternatives.md) |
| What exactly must we build? | [SRS](requirements/software-requirements-specification.md), [MVP](engineering/mvp-specification.md) |
| How do the nodes work together? | [Architecture](architecture/system-architecture.md), [Sequence flows](architecture/sequence-diagrams.md), [Data and trust boundaries](architecture/data-boundaries-and-trust.md) |
| What are the AI agent's permitted behaviors? | [Agent design](architecture/ai-agent-design.md), [Agent contract](ai/agent-contract.md), [AI evaluation](ai/evaluation-plan.md) |
| Which APIs and data shapes? | [Custom API draft](engineering/api-contract.openapi.yaml), [Schemas/fixtures](engineering/fixtures/README.md) |
| Why did we make these tradeoffs? | [ADRs](architecture/architecture-decision-records.md), [Security](architecture/security-privacy-threat-model.md), [Failure modes](architecture/consistency-and-failure-modes.md) |
| How should AI coding agents execute work? | [First vertical slice](engineering/first-vertical-slice.md), [Implementation plan](engineering/implementation-plan.md), [Coding playbook](engineering/coding-agent-playbook.md) |
| How will we convince judges? | [Demo script](demo/three-minute-demo.md), [Experiment matrix](demo/evaluation-and-acceptance.md) |
| What can we safely claim publicly? | [Claims boundaries](compliance/claims-and-limitations.md), [Standards and citations](research/standards-and-validation.md) |
| What are the competition obligations? | [Hackathon rules](hackathon/rules-and-deliverables.md) |
| How do contributions, labels, and bug reports work? | [Repository workflow](engineering/repository-workflow.md), [Contributing](../CONTRIBUTING.md), [Security reporting](../SECURITY.md) |

## Repository status

The repository currently contains documentation and synthetic examples; application implementation and validation are pending.
Use the [root README](../README.md) for the current setup and validation commands.

## Local research

Historical sources and working notes remain in the ignored `.intel/` directory for local development.
Public documentation must remain usable without those files.
Accepted design decisions and public contracts take precedence over historical drafts; neither establishes technical or legal conformance.
