# Repository workflow and error reporting

## Public repository boundary

Keep the public repository focused on source, executable tests, synthetic fixtures, and reviewed documentation.
Store local research and working context in `.intel/`, which is ignored at every depth.
The supplied archive's original manifest is retained locally at `.intel/import-manifest.json` (ignored by Git, not part of the public repository).
Do not upload the original ZIP to the public repository: it includes local research.

The documentation describes a proposed prototype.
Add reproducible startup instructions, application checks, and observed demo results when executable code is introduced.
Do not present design requirements as tested production guarantees.

## Issue triage

Issue forms assign `bug`, `enhancement`, or `documentation` and `needs-triage`.
New and reopened issues and pull requests receive `needs-triage` automatically.
Pull requests touching documentation or repository automation also receive `documentation` or `area:ci`.

A maintainer confirms the reproduction or acceptance criteria, assigns an owner, adds one priority, and removes `needs-triage` when the issue is understood.
Use `priority:p0` for a critical blocker, `priority:p1` for a material core-flow or delivery problem, and `priority:p2` for normal planned work.
Use `area:ai`, `area:credentials`, `area:policy`, `area:web`, or `area:ci` where useful.
Security reports belong in the private process in [SECURITY.md](../../SECURITY.md).

Apply one status label at a time:

1. `status:todo`: accepted and ready to start.
2. `status:implementing`: implementation is underway.
3. `status:tests`: validation is underway.
4. `status:review`: the change is ready for review.
5. Close the issue after the fix is merged and acceptance criteria are met.

Use `status:blocked` in place of the current status when progress cannot continue.
Record the blocker and the condition needed to resume.
Status, priority, and ownership changes are maintainer decisions; the automation does not infer them.

[`.github/labels.json`](../../.github/labels.json) is the managed label inventory.
The Sync repository labels workflow creates or updates those labels on the default branch without deleting unrelated labels.
Changes to that inventory should be reviewed in a pull request.

## Bug and error flow

Capture the commit, affected component, exact user steps, expected outcome, observed outcome, and sanitized evidence in a bug report.
Reproduce the problem through the user-facing flow before changing behavior.
Retain an appropriate regression test and include its result in the pull request.

When application code is added, failures must have stable machine-readable codes and safe user-visible messages.
Keep denied consent, invalid proof, replay, unknown trust status, and unavailable dependencies distinct.
Provide a retry or manual-review path only when the policy permits it.
Never turn an unavailable dependency or unknown trust decision into successful authorization.
Logs and UI errors must omit secrets, raw credentials, complete proofs, and identity records.
Use correlation identifiers to connect sanitized reports to internal diagnostics.

The [API draft](api-contract.openapi.yaml) and [failure-mode contract](../architecture/consistency-and-failure-modes.md) define the proposed outcomes.
A common runtime error envelope remains implementation work; the repository does not yet contain a service implementing these endpoints.

## CI and repository settings

Repository checks run for pushes and pull requests, including changes to documentation and automation.
They check the public file list, private-path exclusion, local documentation links, JSON and YAML syntax, and local API references.
These checks do not replace secret scanning, application tests, dependency review, or security review.
Dependabot proposes weekly updates for Python validation tooling and GitHub Actions.

After the first push, configure the default branch to require pull requests, a review, and the Repository checks status before merging.
Enable GitHub private vulnerability reporting and retain secret scanning and push protection.
Repository settings are separate from workflow files and must be checked on GitHub.
Select a project license before describing the project as licensed open-source software.
