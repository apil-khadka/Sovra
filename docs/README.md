# Sovra - Documentation Index

**Snapshot:** 2026-10-27 · **Status:** synthetic prototype with a business SRS draft; not a production identity system.

Sovra explores whether a **Meta-powered, policy-grounded interoperability planner** can discover compatible verification evidence across independently governed identity systems, while keeping user identity source records in local jurisdiction-controlled domains.
It is a research/demo prototype using **synthetic data** and **simulated jurisdictions**.

> **Design contract:** Meta AI proposes. Approved policies, consent and deterministic code authorize. Issuers sign evidence. Verifiers verify evidence. Relying parties decide legal KYC/CDD sufficiency themselves.

## Reading map

| Question | Document |
| --- | --- |
| Why does Sovra exist, and what is new? | [Vision](product/vision-and-scope.md), [Positioning](product/positioning-and-alternatives.md) |
| What exactly must we build? | [Business SRS](requirements/software-requirements-specification.md) (requirements and production gates), [MVP](engineering/mvp-specification.md) (synthetic milestone) |
| What should we implement next, and what blocks release? | [Business implementation plan](engineering/implementation-plan.md), [36-task backlog](engineering/implementation-backlog.md), [Machine-readable tasks](engineering/implementation-tasks.json) |
| How do the nodes work together? | [Architecture](architecture/system-architecture.md), [Sequence flows](architecture/sequence-diagrams.md), [Data and trust boundaries](architecture/data-boundaries-and-trust.md) |
| What are the AI agent's permitted behaviors? | [Agent design](architecture/ai-agent-design.md), [Agent contract](ai/agent-contract.md), [AI evaluation](ai/evaluation-plan.md) |
| Which APIs and data shapes? | [Custom API draft](engineering/api-contract.openapi.yaml), [Schemas/fixtures](engineering/fixtures/README.md) |
| Why did we make these tradeoffs? | [ADRs](architecture/architecture-decision-records.md), [Security](architecture/security-privacy-threat-model.md), [Failure modes](architecture/consistency-and-failure-modes.md) |
| Which backend stack is selected, and how will its security be verified? | [Java/Spring baseline](architecture/java-spring-baseline.md), [Security validation plan](engineering/security-validation-plan.md) |
| Which mission-critical and security controls does Sovra need? | [Security and mission-critical research](research/security-and-mission-critical-review.md) (priorities, tradeoffs, recovery, and validation) |
| How do local images, extraction, IDs, and enrollment work? | [Federated document lifecycle](architecture/federated-document-lifecycle.md) |
| How will organizations integrate and manage information? | [Developer platform, SDKs, and dashboards](engineering/developer-platform.md), [Issuer-node API draft](engineering/issuer-node-api.openapi.yaml) |
| What would enterprise rigor change? | [Enterprise review](architecture/enterprise-architecture-review.md) (gaps, improvements, new ADRs) |
| How should AI coding agents execute work? | [First vertical slice](engineering/first-vertical-slice.md), [Implementation plan](engineering/implementation-plan.md), [Coding playbook](engineering/coding-agent-playbook.md) |
| How will we convince judges? | [Demo script](demo/three-minute-demo.md), [Experiment matrix](demo/evaluation-and-acceptance.md) |
| Which dated milestone applies to the hackathon? | [Synthetic milestone schedule](engineering/hackathon-milestone-plan.md) |
| What can we safely claim publicly? | [Claims boundaries](compliance/claims-and-limitations.md), [Standards and citations](research/standards-and-validation.md) |
| What are the competition obligations? | [Hackathon rules](hackathon/rules-and-deliverables.md) |
| How do contributions, labels, and bug reports work? | [Repository workflow](engineering/repository-workflow.md), [Contributing](../CONTRIBUTING.md), [Security reporting](../SECURITY.md) |

## Repository status

The repository contains documentation, a Java 25/Spring Boot backend bootstrap, a React frontend bootstrap, and synthetic examples.
The earlier TypeScript prototype was removed; JSON fixtures are preserved as migration evidence.
The G1 vertical slice and security assessment are pending.
Use the [root README](../README.md) for the current setup and validation commands.

## Local research

Historical sources and working notes remain in the ignored `.intel/` directory for local development.
Public documentation must remain usable without those files.
Accepted design decisions and public contracts take precedence over historical drafts; neither establishes technical or legal conformance.
