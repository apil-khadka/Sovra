import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const projectDir = dirname(dirname(fileURLToPath(import.meta.url)));
const sourceCaptions = readFileSync(join(projectDir, "public/source-captions.srt"), "utf8");
const outputDir = join(projectDir, "deliverables");
const outputPath = join(outputDir, "sovra-three-minute.srt");
const openingFrames = 360;
const mapFrames = 470;
const footageFrames = 3806;
const fps = 30;
const footageOffsetMs = Math.round(((openingFrames + mapFrames) / fps) * 1_000);

const toMs = (value) => {
  const [hours, minutes, rest] = value.split(":");
  const [seconds, millis] = rest.split(",");
  return Number(hours) * 3_600_000 + Number(minutes) * 60_000 + Number(seconds) * 1_000 + Number(millis);
};

const timestamp = (milliseconds) => {
  const value = Math.max(0, Math.floor(milliseconds));
  const hours = Math.floor(value / 3_600_000);
  const minutes = Math.floor((value % 3_600_000) / 60_000);
  const seconds = Math.floor((value % 60_000) / 1_000);
  const millis = value % 1_000;
  const pad = (number, digits = 2) => String(number).padStart(digits, "0");
  return `${pad(hours)}:${pad(minutes)}:${pad(seconds)},${pad(millis, 3)}`;
};

const intro = [
  { start: 0, end: 5_500, text: "Sovra — a synthetic identity verification walkthrough." },
  { start: 5_500, end: 12_000, text: "One question: can this credential prove someone is over 18?" },
  { start: 12_000, end: 15_800, text: "One request enters the central planner." },
  { start: 15_800, end: 19_800, text: "The fixture planner proposes. The deterministic guard checks the plan." },
  { start: 19_800, end: 23_600, text: "A valid plan routes issuance and consent to its issuer node." },
  { start: 23_600, end: footageOffsetMs, text: "The holder reviews the claims. Incompatible evidence stops early." },
];

const footage = sourceCaptions
  .trim()
  .split(/\r?\n\s*\r?\n/)
  .map((block) => block.trim().split(/\r?\n/))
  .filter((lines) => lines.length >= 3)
  .map((lines) => {
    const [start, end] = lines[1].split(" --> ");
    return {
      start: toMs(start) + footageOffsetMs,
      end: toMs(end) + footageOffsetMs,
      text: lines.slice(2).join(" "),
    };
  });

const proofStart = Math.round(((openingFrames + mapFrames + footageFrames) / fps) * 1_000);
const proofEnd = Math.round(((openingFrames + mapFrames + footageFrames + 390) / fps) * 1_000);
const ending = [
  { start: proofStart, end: proofStart + 6_500, text: "Fjord and Harbor map to the requested age-over-18 result." },
  { start: proofStart + 6_500, end: proofEnd, text: "Employment returns NO_PATH: no plan, credential, or consent." },
  { start: proofEnd, end: proofEnd + 6_200, text: "Synthetic fixtures. Fixture planner. Live AI is off." },
  { start: proofEnd + 6_200, end: 180_000, text: "Production KYC, keys, hosting, and conformance are not shown." },
];

const cues = [...intro, ...footage, ...ending]
  .sort((a, b) => a.start - b.start)
  .map((cue, index) => `${index + 1}\n${timestamp(cue.start)} --> ${timestamp(cue.end)}\n${cue.text}`)
  .join("\n\n");

mkdirSync(outputDir, { recursive: true });
writeFileSync(outputPath, `${cues}\n`, "utf8");
console.log(`Wrote ${intro.length + footage.length + ending.length} cues to ${outputPath}`);
