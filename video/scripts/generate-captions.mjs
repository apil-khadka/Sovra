import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const projectDir = dirname(dirname(fileURLToPath(import.meta.url)));
const outputDir = join(projectDir, "deliverables");
const outputPath = join(outputDir, "sovra-three-minute.srt");
const fps = 30;
const totalFrames = 5_400;

const cues = [
  [0, 3, "Imagine a local shop needs only to know that a customer is over 18."],
  [3, 6, "But a credential may contain a birth date, document number, and address."],
  [6, 9, "Different schemas can push a simple check toward over-collection."],
  [9, 12, "Sovra starts with a smaller question: age_over_18."],

  [12, 16, "Follow that question through two fictional relying-party apps."],
  [16, 20, "NovaBank and CornerCellar ask the same eligibility question."],
  [20, 23, "The holder reviews the exact evidence before choosing to share it."],
  [23, 26, "Both app flows are local and synthetic."],

  [26, 31, "The core Compose file starts PostgreSQL, Keycloak, a seed job, and a quarantine worker."],
  [31, 37, "Two backend instances, app-a and app-b, share the same PostgreSQL database."],
  [37, 44, "That is the application replica setup; it is not issuer-level separation."],

  [44, 50, "A separate Compose file powers the unfamiliar-schema demonstration with two issuer nodes."],
  [50, 56, "Node A owns its database and signing key. Node B owns a different database and key."],
  [56, 62, "The plan selects the issuer. Public trust metadata is copied; credentials and private keys stay local to each node."],

  [62, 66, "The browser sends a small case selector for Fjord."],
  [66, 71, "The demo server builds a scoped intent and asks the central planner to find a compatible claim."],
  [71, 77, "The fixture plan returns candidate-only with isAdult on synth-2."],
  [77, 82, "A deterministic guard checks that plan and returns GUARD_ACCEPTED."],
  [82, 84, "The browser never chooses or echoes the unfamiliar field."],

  [84, 89, "Before issuance, the holder sees the purpose, issuer, exact claim, expiry, and plan hash."],
  [89, 95, "They can approve, decline, or go back. No proof is shared before approval."],
  [95, 104, "This plan, guard response, and consent screen came from the running synthetic flow."],

  [104, 109, "After approval, the selected issuer signs a scoped synthetic credential."],
  [109, 114, "Verification checks the evidence and records an accepted decision."],
  [114, 118, "The relying party receives one bounded result, not a source identity record."],

  [118, 122, "NovaBank records eligibility evidence in its synthetic onboarding flow."],
  [122, 127, "CornerCellar places a fictional demo order after the synthetic age check."],
  [127, 132, "These are local browser demos, not external production services."],

  [132, 136, "Now test an incompatible input: employment tenure cannot prove age."],
  [136, 140, "The fixture planner returns NO_PATH with a null plan."],
  [140, 144, "No guard result, credential, or consent request follows."],

  [144, 148, "Credentials use P-256/ES256 signatures; vault objects use AES-GCM encryption."],
  [148, 152, "Each object version gets a fresh 32-byte data key and 12-byte nonce."],
  [152, 156, "AES-GCM binds holder identity as associated data."],
  [156, 160, "HKDF-SHA256 derives versioned tenant wrapping keys in this synthetic software provider."],
  [160, 164, "Production KMS is unavailable; its production gate fails closed."],
  [164, 168, "The browser age-check route never reads vault documents."],

  [168, 172, "Ask, plan, guard, consent, and verify are separate steps."],
  [172, 176, "Synthetic fixtures only. FIXTURE planner, live AI off, one local host."],
  [176, 180, "No legal KYC, zero-knowledge proof, production hosting, or external conformance is shown."],
];

const timestamp = (seconds) => {
  const frame = Math.round(seconds * fps);
  const milliseconds = Math.round((frame / fps) * 1_000);
  const hours = Math.floor(milliseconds / 3_600_000);
  const minutes = Math.floor((milliseconds % 3_600_000) / 60_000);
  const wholeSeconds = Math.floor((milliseconds % 60_000) / 1_000);
  const millis = milliseconds % 1_000;
  const pad = (number, digits = 2) => String(number).padStart(digits, "0");
  return `${pad(hours)}:${pad(minutes)}:${pad(wholeSeconds)},${pad(millis, 3)}`;
};

for (const [start, end] of cues) {
  if (start < 0 || end <= start || end * fps > totalFrames) {
    throw new Error(`caption is outside the 180-second edit: ${start}..${end}`);
  }
}

const srt = cues
  .map(([start, end, text], index) => `${index + 1}\n${timestamp(start)} --> ${timestamp(end)}\n${text}`)
  .join("\n\n");

mkdirSync(outputDir, { recursive: true });
writeFileSync(outputPath, `${srt}\n`, "utf8");
console.log(`Wrote ${cues.length} story captions to ${outputPath}`);
