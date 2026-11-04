# Sovra - Documentation Index

**Snapshot:** 2026-11-04 · **Status:** working synthetic Java/React demo with fresh source/runtime evidence; wallet and browser profiles are requalified, and the three-minute story video is rendered and checked; live/provider qualification plus production gates remain pending.

Sovra explores whether a **Meta-powered, policy-grounded interoperability planner** can discover compatible verification evidence across independently governed identity systems, while keeping user identity source records in local jurisdiction-controlled domains.
It is a research/demo prototype using **synthetic data** and **simulated jurisdictions**.

> **Design contract:** Meta AI proposes. Approved policies, consent and deterministic code authorize. Issuers sign evidence. Verifiers verify evidence. Relying parties decide legal KYC/CDD sufficiency themselves.

## Reading map

Start implementation work with the [current continuation guide](engineering/continuation-guide.md), reviewed 2026-11-03.
It reconciles implemented demo features, fresh source/runtime evidence, remaining browser/protocol/public-hosting gates and no-credit verification.

| Question | Document |
| --- | --- |
| How does the current three-minute product walkthrough work? | [Video, subtitles, and current storyboard](demo/three-minute-demo.md) |
| Why does Sovra exist, and what is new? | [Vision](product/vision-and-scope.md), [Positioning](product/positioning-and-alternatives.md) |
| What exactly must we build? | [Business SRS](requirements/software-requirements-specification.md) (requirements and production gates), [MVP](engineering/mvp-specification.md) (synthetic milestone) |
| What should we implement next, and what blocks release? | [Business implementation plan](engineering/implementation-plan.md), [41-task backlog](engineering/implementation-backlog.md), [Machine-readable tasks](engineering/implementation-tasks.json) |
| What is ready for production and larger user volumes? | [Production and capacity assessment](engineering/production-readiness.md), [17 production work items](engineering/implementation-backlog.md#production-readiness-work-breakdown) |
| How do the nodes work together? | [Architecture](architecture/system-architecture.md), [Sequence flows](architecture/sequence-diagrams.md), [Data and trust boundaries](architecture/data-boundaries-and-trust.md) |
| What are the AI agent's permitted behaviors? | [Agent design](architecture/ai-agent-design.md), [Agent contract](ai/agent-contract.md), [AI evaluation](ai/evaluation-plan.md) |
| Which APIs and data shapes? | [Custom API draft](engineering/api-contract.openapi.yaml), [Schemas/fixtures](engineering/fixtures/README.md) |
| Why did we make these tradeoffs? | [ADRs](architecture/architecture-decision-records.md), [Security](architecture/security-privacy-threat-model.md), [Failure modes](architecture/consistency-and-failure-modes.md) |
| Which backend stack is selected, and how will its security be verified? | [Java/Spring baseline](architecture/java-spring-baseline.md), [Security validation plan](engineering/security-validation-plan.md) |
| Which mission-critical and security controls does Sovra need? | [Security and mission-critical research](research/security-and-mission-critical-review.md) (priorities, tradeoffs, recovery, and validation) |
| Which identity/key provider should we implement, and what did the architecture review find? | [Identity and attested key-provider architecture](architecture/identity-key-provider-architecture.md), [Provider decision v0.2](architecture/decisions/SOV-004-provider-key-cache-contracts.md) |
| How do local images, extraction, IDs, and enrollment work? | [Federated document lifecycle](architecture/federated-document-lifecycle.md) |
| How will organizations integrate and manage information? | [Developer platform, SDKs, and dashboards](engineering/developer-platform.md), [Issuer-node API draft](engineering/issuer-node-api.openapi.yaml) |
| What would enterprise rigor change? | [Enterprise review](architecture/enterprise-architecture-review.md) (gaps, improvements, new ADRs) |
| How should AI coding agents execute work? | [First vertical slice](engineering/first-vertical-slice.md), [Implementation plan](engineering/implementation-plan.md), [Coding playbook](engineering/coding-agent-playbook.md) |
| How will we convince judges? | [Demo script](demo/three-minute-demo.md), [Experiment matrix](demo/evaluation-and-acceptance.md) |
| How do the two demo issuers run separately? | [Dual-issuer topology](demo/dual-issuer-topology.md) (standalone local synthetic stacks) |
| How is unfamiliar-schema proof demonstrated? | [Interoperability demo](demo/interoperability.md) (four-schema governed journey) |
| How is planner discovery scored? | [Planner evaluation](ai/planner-evaluation.md) (frozen corpus v2, guard-adjudicated) |
| Which dated milestone applies to the hackathon? | [Synthetic milestone schedule](engineering/hackathon-milestone-plan.md) |
| What can we safely claim publicly? | [Claims boundaries](compliance/claims-and-limitations.md), [Standards and citations](research/standards-and-validation.md) |
| What are the competition obligations? | [Hackathon rules](hackathon/rules-and-deliverables.md) |
| How do contributions, labels, and bug reports work? | [Repository workflow](engineering/repository-workflow.md), [Contributing](../CONTRIBUTING.md), [Security reporting](../SECURITY.md) |

## Repository status

The repository contains a Java 25/Spring Boot backend, React application, synthetic identity/document workflows, SDKs, operator/product desks and mock relying-party integration examples.
The earlier TypeScript prototype was removed; JSON fixtures are preserved as migration evidence.
The synthetic vertical slice has automated source and runtime evidence; the wallet's 390px responsive check and both local browser profiles now pass, and the three-minute fixture-mode video is verified locally at 1920×1080 and 30 fps.
The video does not show a live Meta model call; the real Baseten smoke is recorded separately in [live integration evidence](ai/live-integration.md).
Live/provider qualification, external wallet conformance, deployed production security assessment and capacity qualification remain pending.
Use the [root README](../README.md) for the current setup and validation commands.

## Local research

Historical sources and working notes remain in the ignored `.intel/` directory for local development.
Public documentation must remain usable without those files.
Accepted design decisions and public contracts take precedence over historical drafts; neither establishes technical or legal conformance.
