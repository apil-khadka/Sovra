# Sovra synthetic walkthrough

This project packages a real browser recording of Sovra's local synthetic unfamiliar-schema flow into a captioned three-minute video.

The finished H.264 video and SRT captions are in [`deliverables/`](deliverables/).

The capture uses fictional issuers and credentials, the fixture planner, and local demo backends.

Live AI is disabled for the recording.

The video does not claim legal KYC, production hosting or keys, real identity-data processing, or external wallet conformance.

## Render the video

Install dependencies with `npm ci`.

Start Remotion Studio with `npm run dev` to inspect the composition in the integrated browser.

Generate the sidecar captions with `npm run captions`.

Render the H.264 MP4 with `npm run render:sovra`.

The MP4 and SRT are written to `deliverables/`.

The Remotion bundle and preview frames are written under `out/`, which is ignored by Git.

## Refresh the browser capture

Follow the synthetic dual-issuer setup in [`docs/demo/interoperability.md`](../docs/demo/interoperability.md).

With the local demo server running on port 5176, run:

```sh
DEMO_BASE=http://127.0.0.1:5176 ARTIFACT_DIR=/tmp/sovra-3-minute-source \
  pnpm --dir demo run record:demo
```

Copy `sovra-synthetic-demo.mp4` and `captions.srt` from that artifact directory into `video/public/` before rendering.

The captured browser footage is a source asset; the Remotion scenes add the opening, flow explanation, evidence summary, and scope card.
