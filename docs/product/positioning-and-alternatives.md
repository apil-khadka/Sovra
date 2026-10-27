# Positioning, alternatives and differentiation

## User problem and narrow wedge

A foreign relying party may recognize neither a jurisdiction's identity schema nor its assurance vocabulary and therefore fall back to requesting full document scans and manual expert mapping. Sovra tests whether a model can **discover possible evidence paths** across unfamiliar issuer capability descriptions and cite **specific supplied policies**, instead of hard-coding country-to-country adapters.

**Pitch:** An AI-native verification-planning layer for sovereign credential networks—not a new government registry and not an AI judge of legal compliance.

## What already exists / should not be claimed as invention

- Verifiable credentials, holder wallets, trust registries and consent are established technical concepts, not new Sovra inventions.
- EUDI/eIDAS and OpenID standards already support large elements of cross-border identity interoperability.
- MOSIP and SSI wallets show existing approaches to national identity infrastructure.
- Enterprise identity orchestration and KYC vendors already combine providers and policy routing. A language model that merely chooses a provider is a weak novelty claim.

## Experimentally testable contribution

A single model-guided planner with **read-only discovery tools**, **grounded source citations**, and a **deterministic plan checker** attempts compatibility planning for a third mock issuer whose schema was not inserted into prompts or code-specific mappings before evaluation. Compare with a static known-schema mapping baseline. Evaluate failures, not only successes.

## Choice of showcase

Use a synthetic Nepal-to-Australia age-assurance exchange to show the conceptual story; use an unknown third *fictional* issuer to demonstrate adaptability. Do not imply the Nepal and Australian governments endorse or participate in the prototype.

## Audience and value

| Audience | Prototype evidence of value | What is not established |
| --- | --- | --- |
| Wallet holder | Explicitly approves a minimized attribute request | Robust production wallet recovery and key custody |
| Business verifier | Receives trustworthy signed evidence for a configured purpose | That evidence alone satisfies AML/CTF obligations |
| Identity network/issuer | Publishes schemas, authorization scope and verification metadata | Government accreditation or real cross-border federation |
| Integration engineer | Can inspect provenance of an AI-proposed mapping | That model outputs are always correct on unseen real schemas |
