# Sovra product story

This project renders a silent, three-minute walkthrough with animated block diagrams and actual browser captures from the local synthetic demos.
The story moves from the over-collection problem through the two app demos, both Compose topologies, fixture plan and guard JSON, holder consent, verification, a fail-closed refusal, and the separate backend encryption path.

The MP4 has no fixed video header or burned-in caption bar.
The synchronized subtitle track is delivered as a separate SRT file in `deliverables/`.
The current render is H.264 at 1920×1080 and 30 fps, with a duration of exactly 180 seconds.

## Visual system

Scene titles share one fixed right-hand column, size, and top alignment.
Body copy, JSON, section labels, and scene footers use consistent type scales and spacing.
Callouts use square-edged markers rather than pill-shaped badges.
The project uses display serif for scene titles, sans serif for explanation, and monospace for protocol values.

## Evidence and limits

NovaBank and CornerCellar run against the root Compose stack through the demo server on port 5174.
The unfamiliar-schema page runs against the separate dual-issuer Compose stack through the demo server on port 5176.
Both runtimes use synthetic records, and live AI is disabled.
The plan and guard JSON in the video are actual outputs from the local fixture flow, not from a live model call.
The separate Baseten live smoke from 2026-10-29 is documented in [live-integration.md](../docs/ai/live-integration.md); this video does not present that run.
That smoke used prompt version 2 and guard version 1, while the current fixture demo contract uses prompt version 3 and guard version 2.
The video shows fixture output and guard version 2, but it does not display the planner prompt version or a live Meta invocation.
The smoke is historical, version-specific evidence and does not qualify the current prompt and guard pair.

The root Compose `app-a` and `app-b` instances share one PostgreSQL database.
The separate dual-issuer Compose file runs two local nodes with separate databases, networks, and signing keys, but one developer host still controls both.
The video labels this as local logical separation rather than sovereign-host isolation.

The vault diagram describes the implemented backend encryption path, not a document read from the age-check browser journey.
The local synthetic provider uses software-derived wrapping keys.
Production KMS/HSM, production hosting, legal KYC, zero-knowledge proofs, and external wallet conformance are not demonstrated.

## Preview and render

Install dependencies with `npm ci`.
Run `npm run dev -- --no-open` and open the printed URL in the integrated browser to inspect the Remotion composition.
Generate captions with `npm run captions`.
Render the H.264 MP4 with `npm run render:sovra`.

The finished MP4 and SRT are written to `deliverables/`.
Remotion writes build output under the ignored `out/` directory.

## Refresh browser evidence

Start the root synthetic Compose stack and the separate dual-issuer stack using the documented commands in `docs/demo/kyc-demo-apps.md` and `docs/demo/interoperability.md`.
Run the root-backed demo server on port 5174 with its existing `demo/.env.local` credentials.
Run the interop-only demo server on port 5176 with the dual-issuer token directory and live planning disabled.

Capture current application screenshots and redacted plan/guard evidence with `npm run capture:scenes`.
Refresh the clean browser recording with:

```sh
DEMO_BASE=http://127.0.0.1:5176 ARTIFACT_DIR=/tmp/sovra-interop-source \
  node demo/record-interop-demo.mjs
```

Copy the resulting `sovra-synthetic-demo.mp4` into `video/public/` before rendering.
The browser recording contains no caption overlay; its beat captions are saved separately for review.
