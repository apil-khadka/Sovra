# Three-minute hackathon demo — current artifact and submission notes

## Current artifact

The current [MP4 walkthrough](../../video/deliverables/sovra-three-minute.mp4) is exactly 180 seconds at 1920×1080 and 30 fps.
Its [40-cue subtitle file](../../video/deliverables/sovra-three-minute.srt) is delivered separately.
The video is silent and uses authentic browser captures from local synthetic applications.
The planner is in `FIXTURE` mode, live AI is disabled, and the JSON shown is the actual fixture-plan and guard output.
The video does not show a live Meta model invocation.

The repository records a real Baseten/Muse Spark Open smoke from 2026-10-29 in [live-integration.md](../ai/live-integration.md).
That historical smoke used prompt version 2 and guard version 1, while the current fixture demo contract uses prompt version 3 and guard version 2.
The video shows fixture output and guard version 2, but it does not display the planner prompt version.
The old smoke proves that a live call worked at that point; it does not qualify the current prompt and guard versions or appear in the current video.
Do not describe the fixture video as a live-model recording.

## Current video sequence

| Time | Scene | Evidence shown |
| --- | --- | --- |
| 0:00–0:12 | Over-collection problem | One age question compared with unnecessary identity fields |
| 0:12–0:26 | Two relying-party apps | NovaBank and CornerCellar request the same age fact |
| 0:26–0:44 | Root Compose topology | Two app instances share the root database and supporting services |
| 0:44–1:02 | Dual-issuer Compose topology | Separate local databases and signing keys on one developer host |
| 1:02–1:24 | Request, fixture plan, and guard JSON | Browser case selector, candidate-only plan, and `GUARD_ACCEPTED` output |
| 1:24–1:44 | Holder consent | The holder reviews the exact synthetic claim before approval |
| 1:44–1:58 | Recorded browser result | The local synthetic Fjord flow reaches `ACCEPTED` |
| 1:58–2:12 | Relying-party outcomes | The two demo apps show their distinct synthetic outcomes |
| 2:12–2:24 | Fail-closed refusal | Employment tenure returns `NO_PATH` with a null plan before guard or consent |
| 2:24–2:48 | Signing and encryption | P-256/ES256 credential signing is separated from AES-GCM vault encryption |
| 2:48–3:00 | Closing principle | Ask, map, consent, and verify remain distinct decisions |

## Submission alignment

The captured participant guide calls for a working product, a video no longer than three minutes, and substantive eligible Meta model use.
It also says model invocation should be demonstrated rather than substituted with a mock.
The current video demonstrates the product and its fixture-mode behavior, but it does not satisfy that live-invocation demonstration by itself.
If the submission requires the invocation to appear in the video, make a truthful updated capture with the current prompt and guard versions after confirming the provider's no-charge limits.
If the portal accepts separate evidence, submit the dated Baseten smoke with its model, prompt, and guard versions clearly labeled.
Never replay a prior response as if it were a fresh live call or describe fixture output as model output.

Before submitting, confirm the selected track, accepted collaborator list, exact portal fields, public repository branch, and judge-accessible demo instructions.
Local addresses such as `127.0.0.1` are not judge-accessible links.
The repository's [hackathon requirements checklist](../hackathon/rules-and-deliverables.md) records the remaining submission checks.
