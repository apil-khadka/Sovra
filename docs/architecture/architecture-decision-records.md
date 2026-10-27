# Architecture decision records (candidate decisions)

The statuses below indicate *design choices*, not implemented or independently audited properties. They reconcile the October 26 architecture review and October 27 AI-native product decision.

| ADR | Status | Decision and rationale | Revisit when |
| --- | --- | --- | --- |
| 001 Federated authority | Adopted premise | Country issuer domains own sources and signing authority; public metadata federation; no global citizen data store | Genuine multi-country governance offered |
| 002 Few deployables | Proposed MVP | Modular TS backend; two country instances with separate data/config/keys; avoid default microservice sprawl | Independent scaling/team ownership justified |
| 003 Narrow attestations | Proposed MVP | Use signed `age_over_18` attestations, **not** UI-redacted JWTs or fake ZK | Tested SD-JWT or proof profile available |
| 004 Standards honesty | Proposed MVP | First build explicit demo signed-proof API; only claim OID4VCI/VP conformance when tested end-to-end against chosen profile | Reliable interoperable SDK confirmed |
| 005 Trust scope | Required design | Trust decision must bind issuer + credential type + authorization scope + trust epoch + purpose | Real issuer accreditation available |
| 006 AI advisory boundary | Required design | Meta proposes grounded structured plans; code and human approved policy decide | Independently verified, governed AI policy update scheme |
| 007 Consent | Required design | Approval must name RP, purpose, claims and expiration; no background export | A standard audited wallet integration available |
| 008 Freshness/replay | Required design | Fail closed for unknown status as configured; atomic session nonce replay protection | Real risk-policy agreement exists |
| 009 Local outbox later | Deferred | Add transactional outbox only when async status publication creates a demonstrated consistency gap | Async worker added |
| 010 Observability | Proposed MVP | Sanitize tool/correlation traces; metric counts and rejection reasons | Real user data introduced |
| 011 Evidence vs KYC | Required design | Return verifiable evidence, **not** a regulator's CDD verdict | Regulated RP contract and legal review |
| 012 Build AI-native | Proposed differentiator | Test *unseen* issuer schema + policy mapping with tool grounding against static baseline | Model incapable of reliable mapping on tests |

See the private local review in `.intel/sources/02-trustmesh-architecture-review-v2-2026-10-26.md` (ignored by Git, not part of the public repository) for earlier G01–G18 gap records, consistency contracts, and infrastructure and production alternatives.
