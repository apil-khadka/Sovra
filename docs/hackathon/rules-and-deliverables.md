# Hackathon organizer requirements (captured participant guide)

**Source:** Organizer participant guide, local capture `.intel/sources/meta-hackathon-participant-guide-captured-2026-10-27.txt` (excluded from Git). Check official updates/Discord before submission.

- **Event:** Meta Global AI Developer Hackathon by Cerebral Valley; kickoff Oct 26 2026, build period Oct 27–Nov 4 2026.
- **Deadline:** Nov 4, 2026 at 9:00 PM US Eastern, equivalent to **Nov 5 at 7:45 AM Nepal Standard Time** (EST after US DST ends).
- **Themes:** Build for Your World; Push the Frontier.
- **Models:** substantive integration with eligible Meta Model API models or Meta open-weight models; organizer guide mentions Muse Spark family, Muse Wonder, Muse Image, Muse Voice Transcribe, SAM 3.1, Muse Glimmer/Muse Spark Open, and Muse Code developer tooling.
- **Repo:** publicly accessible runnable GitHub repo; identify all approved collaborators; up to four participants. Only hackathon-period work is eligible for submission; prior ideas or outside libraries may be used within the organizer's rules, but old project code/history must not be presented as newly authored hackathon work.
- **Video:** at most three minutes, demonstrate working product, not slides alone; distinguish pre-existing work from new additions.
- **Judging:** initial eligibility/theme/Meta-model validation; four equally weighted areas reported in guide: Impact, Use of Meta AI Tooling, Technical Depth & Execution, Demo. Do not invent different track-specific weights for indie vs startup.
- **Credits:** guide mentions Meta API credit offer (reported $150, with billing/setup conditions). Do not assume the offer is active or that a credit card is unnecessary. Partner offers may require separate eligibility.
- **Baseten:** guide/FAQ context says Muse Spark Open model reference `meta-models/muse-spark-open-1026`; check actual dashboard and availability rather than assuming a model name works.

## Submission checks

1. New work after kickoff distinguished from background idea/prior public libraries.
2. Repo public, reproducibly runnable, no secrets, no private `.intel` files.
3. Model invocation demonstrated, not mocked or substituted.
4. 3-minute demo shows both success and hard failure; user consent and security gates visible.
5. Credits/permissions and approved member eligibility verified against official records.
6. Links, recording access, README, and exact event submission portal tested.

## Current project evidence (2026-11-04)

The public submission-ready code and video are on the [`fix/security-and-demo-ux` branch](https://github.com/apil-khadka/Sovra/tree/fix/security-and-demo-ux).
The default `main` branch does not include this branch's current video and documentation updates, so submit the branch URL or merge the changes before using a repository-root link.
The [three-minute MP4](../../video/deliverables/sovra-three-minute.mp4) is exactly 180 seconds at 1920×1080 and 30 fps, with a separate [SRT subtitle file](../../video/deliverables/sovra-three-minute.srt).
The recording is a working synthetic product walkthrough; it uses fixture planning with live AI off and does not show a live model invocation.
The repository records a real Baseten/Muse Spark Open smoke from 2026-10-29, but that run used prompt version 2 and guard version 1; the current fixture contract uses prompt version 3 and guard version 2.
The video shows the guard version but does not display the planner prompt version.
Use the dated smoke only as version-labeled historical evidence, and do not claim that the current recording demonstrates it.
The current browser links use loopback hosts, so they are not accessible to judges; provide reproducible run instructions or a tested public demo URL if the portal requires one.
See the [current demo storyboard](../demo/three-minute-demo.md) and [live-integration record](../ai/live-integration.md) before writing submission claims.
