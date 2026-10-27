# Security reporting

This repository currently contains a prototype design and synthetic examples.
There is no supported production release or production security assurance.

Do not report vulnerabilities, exposed secrets, or identity data in public issues or pull requests.
Use [GitHub private vulnerability reporting](https://github.com/apil-khadka/Sovra/security/advisories/new).
If private reporting is unavailable, use the repository owner's publicly listed contact to request a private channel before sharing details.
No response-time guarantee is currently offered.

Include the affected commit, a minimal reproduction using synthetic data, expected and observed behavior, and the likely impact.
Redact tokens, private keys, credentials, personal data, and complete signed proofs.
If a credential has leaked, revoke or rotate it promptly; removing it from the working tree is insufficient.

The [threat model](docs/architecture/security-privacy-threat-model.md), [trust boundaries](docs/architecture/data-boundaries-and-trust.md), and [claims and limitations](docs/compliance/claims-and-limitations.md) describe the intended security scope.
