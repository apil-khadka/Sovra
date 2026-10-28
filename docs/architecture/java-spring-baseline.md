# Java and Spring backend baseline

**Decision date:** 2026-10-27.
**Status:** selected backend direction; implementation and security verification pending.

Sovra will use Java's latest released LTS line and Spring Boot for its business backend, with security, privacy, correctness, and maintainability taking priority over throughput optimization.
The selected LTS is Java 25.
The repository now contains a Java backend bootstrap (`backend/`, SOV-003) and the TypeScript prototype was removed; this decision does not describe a completed feature migration or production-ready system.

## Version baseline

The following stable releases were checked against official documentation, release records, and the two published Maven BOM POMs on the decision date.
They are implementation candidates to pin and resolve together, not an installed or tested dependency graph.

| Component | Selected baseline | Evidence |
| --- | --- | --- |
| JDK | Java 25 LTS, Eclipse Temurin; latest observed release `25.0.5+8` | [Java LTS roadmap](https://www.oracle.com/java/technologies/java-se-support-roadmap.html), [Temurin release](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.5+8) |
| Spring Boot | 4.1.2 | [Release](https://github.com/spring-projects/spring-boot/releases/tag/v4.1.2), [Java compatibility](https://docs.spring.io/spring-boot/system-requirements.html) |
| Spring Framework | 7.0.10, managed by Boot | [Boot BOM](https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-dependencies/4.1.2/spring-boot-dependencies-4.1.2.pom) |
| Spring Security | 7.1.2, managed by Boot | [Boot BOM](https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-dependencies/4.1.2/spring-boot-dependencies-4.1.2.pom) |
| Spring AI | 2.0.2, with its separate BOM | [Release](https://github.com/spring-projects/spring-ai/releases/tag/v2.0.2), [Boot compatibility](https://docs.spring.io/spring-ai/reference/getting-started.html), [AI BOM](https://repo.maven.apache.org/maven2/org/springframework/ai/spring-ai-bom/2.0.2/spring-ai-bom-2.0.2.pom) |
| Nimbus JOSE+JWT | 10.3 (Sovra-owned JOSE substrate; not a protocol implementation) | [Product](https://connect2id.com/products/nimbus-jose-jwt), [Central](https://repo.maven.apache.org/maven2/com/nimbusds/nimbus-jose-jwt/10.3/) |

Java 27 is a newer feature release but is not LTS.
Boot 4.1.2 documents compatibility with Java 17 through 27, which includes Java 25.
Spring AI 2.0.x documents support for Boot 4.0.x and 4.1.x.
The cited Temurin release confirms the release name; installation must still verify the actual OS/architecture artifact, checksum, and container digest.

Use the Boot parent/BOM and import `org.springframework.ai:spring-ai-bom:2.0.2` separately.
Let Boot manage Framework and Security rather than independently choosing their latest versions.
Do not copy a rolling documentation example's older AI BOM version without checking the selected release.
Review the resolved dependency tree, licenses, checksums/provenance, and vulnerability findings before accepting the baseline.
Use stable releases and pinned build inputs; exclude preview language features, EA builds, milestones, release candidates, and snapshots.
Revalidate supported patch versions at implementation and each release rather than treating this dated table as permanent.

[Temurin's maintenance and support policy](https://adoptium.net/support/) is distinct from Oracle JDK licensing and support.
JDK LTS does not extend the support period of Boot, Security, AI, or their dependencies.
Track supported framework lines and [Spring advisories](https://spring.io/security-policy/) separately, and evaluate a commercial support contract where an operational SLA is required.

## Application shape

Use Maven with a pinned wrapper and Java 25 toolchain/compiler release, Spring MVC, Spring Security, PostgreSQL, Spring JDBC, and versioned SQL migrations.
Choose and pin remaining dependency versions during implementation after license, maintenance, and compatibility review.
Keep the deterministic domain modules independent of controllers, database clients, and AI adapters so their decisions can be tested directly.

Do not use the Java Security Manager as an image/OCR sandbox: [Java 25 documentation](https://docs.oracle.com/en/java/javase/25/security/security-manager-is-permanently-disabled.html) states it has been permanently disabled since JDK 24.
Use reviewed process/OS/container/VM isolation appropriate to hostile document parsing, with separate workload identity, constrained resources, and restricted egress.
The [security research](../research/security-and-mission-critical-review.md) explains the proposed controls and their evidence boundary.

Organize modules around issuer authority and signing, verifier decisions, trust metadata, consent, and AI planning.
Use a small number of deployable processes, with issuer instances separated by their actual authority, database credentials, configuration, and signing permissions.
A modular monolith is a code organization choice; it does not remove jurisdiction or issuer trust boundaries.
React/TypeScript can remain a browser client, with explicit versioned API contracts as the language boundary.

PostgreSQL transactions and constraints must enforce durable nonce consumption and issuance idempotency across instances and restarts.
Store the consent/plan binding and the trust/status versions used in each verification decision.
Choose exact commit, retry, snapshot, and failure semantics before implementing the transaction.
Use managed KMS/HSM signing for production with per-issuer key permissions and tested rotation/compromise procedures.
Never put production signing keys into source code, prompts, browser storage, or an application configuration file.

Use explicit request authorization and enable service-level authorization where required.
[Spring Security method authorization](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html) is not activated merely by adding the security starter.
Verify that every protected service entry path is covered, including proxy/self-invocation limitations.
Keep [CSRF protection](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html) for cookie-authenticated browser mutations and define API-token authentication separately.
Set narrow CORS, serialization, request-size, concurrency, and timeout policies explicitly.

Restrict [Actuator endpoints](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html) by exposure, authorization, and network access.
Detailed environment, heap, logs, and configuration information must not become public troubleshooting endpoints.
Test the packaged production configuration rather than relying on default behavior observed in a test profile.

## Spring AI boundary

Spring AI is the Java integration framework for external or locally hosted models; it does not select or supply Sovra's model by itself.
Use its chat, structured-output, and bounded tool-calling APIs behind a narrow planner interface.
The [existing agent contract](../ai/agent-contract.md) remains authoritative: the model proposes, and deterministic policy, consent, and verification code authorize.

Only schemas, approved policy excerpts, and minimized non-sensitive context may reach the model.
No raw identity documents, real dates of birth, private keys, bearer tokens, or complete credentials belong in planner requests or tool results.
Keep tools read-only, scoped per request, and bounded by call count, execution time, and output size.
Do not expose signing, proof acceptance, consent approval, or policy modification as model tools.

[Spring AI tool execution](https://docs.spring.io/spring-ai/reference/api/tools.html) happens in the application, so each callback is an authorization boundary.
Use application-owned caller/tenant context, validate arguments, check current permissions, and sanitize results/errors before returning them to the model.
Keep resolver fallback disabled and avoid shared default tools that unintentionally broaden the tools available on individual requests.
Do not treat a declared tool schema as authorization.

[Structured-output conversion](https://docs.spring.io/spring-ai/reference/api/structured-output/converters.html) is not a security verdict.
Require bounded parsing, strict schema validation, and independent semantic validation of issuers, claims, policy versions, citations, purpose, and disclosure budgets.
Reject unsupported or ambiguous evidence mappings even if the JSON fits a Java record.

Keep [prompt/completion and tool argument/result observability](https://docs.spring.io/spring-ai/reference/observability/index.html) disabled for sensitive content.
Also inspect HTTP logging, custom advisors, memory stores, exception handling, exporters, and provider-side retention.
Test the complete egress/telemetry path with synthetic sensitive canaries; configuration defaults alone are insufficient evidence.

The exact Meta provider, endpoint, model ID, authentication, request format, tool loop, structured output, streaming, and failure behavior require a live contract test using synthetic inputs.
Generic provider support or an API-compatible label does not establish compatibility with the chosen deployment.
Use a narrow Java adapter if the selected endpoint needs one; keep the domain and authorization modules independent of that choice.

## Migration and production gates

First reproduce one complete synthetic issuance, consent, guarded plan, and verification flow on the selected Java baseline.
Run both valid and adversarial cases through real HTTP and PostgreSQL, including two-instance replay races and dependency outages.
Preserve the existing fixtures and behavioral contracts as migration evidence, with independently reviewed security assertions rather than assuming prototype tests are sufficient.
Keep existing TypeScript checks runnable until the Java replacement has equivalent reviewed behavior and its own CI gates.

Select the credential proof profile and immutable library release before claiming OpenID4VCI, OpenID4VP, SD-JWT, or wallet interoperability.
Spring Security's OAuth/OIDC facilities and JOSE primitives do not establish credential-protocol completeness.
Require external interoperability fixtures and negative tests for the exact chosen profile.

Implement the [security validation plan](../engineering/security-validation-plan.md) and close its production gates before handling real sensitive data.
Framework selection, successful builds, or passing scanners alone do not establish production security or legal compliance.
The [implementation plan](../engineering/implementation-plan.md) sequences Java migration separately from sensitive-document and customer release work.
The [task backlog](../engineering/implementation-backlog.md) assigns API/service authorization, scoped runtime identities, replay-safe recovery, provider cache contracts, artifact admission and semantic readiness to explicit tasks.
SEC-01 through SEC-44 and MC-01 through MC-10 require actual packaged/deployed evidence, independently assessed ASVS applicability and retested findings for the release scope.
