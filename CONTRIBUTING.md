# Contributing

Start with the [documentation index](docs/README.md) and the [first vertical slice](docs/engineering/first-vertical-slice.md).
The repository currently contains design documentation and synthetic examples.
Describe proposed capabilities as planned until working code and tests demonstrate them.

## Issues

Search existing issues before opening a new one.
Choose the bug, feature, or documentation form and include the affected component and acceptance criteria.
For a bug, provide a minimal reproduction, expected and observed behavior, the commit or version, and sanitized error details.
Include an error code or correlation identifier when available.
Never upload identity records, credentials, tokens, private keys, or private research.
Follow [SECURITY.md](SECURITY.md) for security reports.

Maintainers use the [label and triage workflow](docs/engineering/repository-workflow.md) to prioritize work.

## Changes

1. Create a focused branch such as `docs/navigation` or `fix/session-replay`.
2. Link the issue and define observable acceptance criteria before implementation.
3. For behavior fixes, reproduce the failure through the user-facing flow first, then retain a regression test at the appropriate layer.
4. Update relevant contracts and documentation alongside behavior changes.
5. Run repository checks and any application checks relevant to the change.
6. Open a pull request using the template, including validation results and remaining limitations.

Keep pull requests small enough to review as one coherent change.
Use established dependencies and commit their lockfiles when application tooling is introduced.
Do not commit build artifacts, local research, or environment-specific files.
Do not manually edit generated files or changelogs.

## Checks

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/check_repository.py
git diff --check
git check-ignore -v .intel/README.md
```

The repository checker includes tracked files even if they match `.gitignore`.
Ignoring a previously committed file does not remove it from Git or its history.
Review the complete staged diff before committing.

## Review and merge

Require a passing Repository checks result and review of behavior, privacy boundaries, and failure cases before merging.
Once the initial branch is published, configure the default branch to require that check and a pull request review.
Workflow files alone do not enforce branch protection.

Treat missing trust data, invalid proof, denied consent, and dependency failures as explicit outcomes.
Do not turn a failed or unknown verification into success.
Follow the [failure-mode contract](docs/architecture/consistency-and-failure-modes.md) and document any new error behavior.
