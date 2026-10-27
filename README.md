# Sovra

Sovra is the repository for the TrustMesh identity-interoperability prototype.
The prototype explores how a Meta-powered AI planner can propose verification evidence across simulated jurisdictions, while deterministic policy checks, holder consent, and issuer signatures control authorization.

**Current status:** documentation and synthetic examples only.
There is no runnable application, deployed demo, or completed security evaluation yet.
Architecture documents describe intended behavior rather than implemented guarantees.

## Start here

- [Documentation index](docs/README.md): product scope, architecture, requirements, and implementation plan.
- [First vertical slice](docs/engineering/first-vertical-slice.md): the initial implementation target.
- [API draft](docs/engineering/api-contract.openapi.yaml): proposed orchestration endpoints.
- [Acceptance criteria](docs/demo/evaluation-and-acceptance.md): evidence required for the demo.
- [Claims and limitations](docs/compliance/claims-and-limitations.md): prototype and standards boundaries.

The demo is designed for synthetic data and simulated jurisdictions.
It does not establish legal KYC compliance, government approval, or production identity-system readiness.

## Repository checks

Use Python 3.11 or newer:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/check_repository.py
```

The same checks run in GitHub Actions.
They validate public file boundaries, local Markdown links, JSON and YAML syntax, and local references in the API draft.
Application lint, type checks, unit tests, and end-to-end tests must be added with the first executable code.

## Contributing and reporting problems

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request.
Use the issue forms for bugs, feature requests, and documentation problems.
Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md).
The [repository workflow guide](docs/engineering/repository-workflow.md) explains labels and triage.

Local research belongs in ignored `.intel/` directories.
Only reviewed public documentation, synthetic fixtures, and project source belong in Git.

## License

No license has been selected yet. All rights are reserved by default until a license is added.
