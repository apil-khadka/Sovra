# Sovra

Sovra is an identity-interoperability prototype.
The prototype explores how a Meta-powered AI planner can propose verification evidence across simulated jurisdictions, while deterministic policy checks, holder consent, and issuer signatures control authorization.

**Current status:** documentation, a Java 25/Spring Boot backend bootstrap, a React frontend bootstrap, and synthetic examples.
The earlier TypeScript prototype was removed; JSON fixtures in `tests/fixtures/` and `docs/engineering/fixtures/` are preserved as migration evidence.
Java 25 LTS with Spring Boot is the [selected backend direction](docs/architecture/java-spring-baseline.md); the G1 vertical slice, deployed demo, and security evaluation are pending.
Architecture documents describe intended behavior rather than implemented guarantees.

## Start here

- [Documentation index](docs/README.md): product scope, architecture, requirements, and implementation plan.
- [Software Requirements Specification](docs/requirements/software-requirements-specification.md): business scope, testable requirements, security, and release acceptance.
- [First vertical slice](docs/engineering/first-vertical-slice.md): the initial implementation target.
- [Business implementation plan](docs/engineering/implementation-plan.md) and [task backlog](docs/engineering/implementation-backlog.md): delivery gates, dependencies, acceptance criteria and GitHub tasks.
- [API draft](docs/engineering/api-contract.openapi.yaml): proposed orchestration endpoints.
- [Acceptance criteria](docs/demo/evaluation-and-acceptance.md): evidence required for the demo.
- [Security validation plan](docs/engineering/security-validation-plan.md): proposed adversarial tests and production evidence gates.
- [Identity/key-provider architecture](docs/architecture/identity-key-provider-architecture.md): provider recommendation, current architecture findings and development/live-data gates.
- [Claims and limitations](docs/compliance/claims-and-limitations.md): prototype and standards boundaries.

The demo is designed for synthetic data and simulated jurisdictions.
It does not establish legal KYC compliance, government approval, or production identity-system readiness.

## Repository checks

The backend needs JDK 25 (Eclipse Temurin 25.0.5 or newer) with no other
prerequisites besides Docker for integration tests; the frontend needs
Node.js 22 with pnpm; repository validation needs Python 3.11 or newer.

```sh
(cd backend && ./mvnw verify)
./scripts/smoke-two-instance.sh
pnpm --dir frontend install
pnpm --dir frontend run build
pnpm --dir frontend run lint
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/check_repository.py
```

The same checks run in GitHub Actions (`Application checks` and
`Repository checks` workflows).
They validate the Java build and integration tests, the frontend build and
lint, public file boundaries, local Markdown links, JSON and YAML syntax,
and local references in the API draft.

## Contributing and reporting problems

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request.
Use the issue forms for bugs, feature requests, and documentation problems.
Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md).
The [repository workflow guide](docs/engineering/repository-workflow.md) explains labels and triage.

Local research belongs in ignored `.intel/` directories.
Only reviewed public documentation, synthetic fixtures, and project source belong in Git.

## License

No license has been selected yet. All rights are reserved by default until a license is added.
