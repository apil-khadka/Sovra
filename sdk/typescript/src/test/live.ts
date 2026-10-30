import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import { SovraClient } from "../index.js";

/**
 * Live-stack contract tests (SOV-021): every test talks to a real
 * backend over HTTP. The stack must be up
 * (`docker compose up --build -d`); machine accounts mint
 * through the compose database exactly like the browser suite.
 */
export const BASE =
  process.env["SOVRA_SDK_BASE"] ?? "http://localhost:8080";
const DB_CONTAINER =
  process.env["SOVRA_E2E_DB_CONTAINER"] ?? "sovra-db-1";
const DB_PASSWORD =
  process.env["SOVRA_DB_ADMIN_PASSWORD"] ?? "sovra-dev-only";

export const ISSUER_ID = "https://sovra.example/issuers/synth-1";
export const ADULT_VCT = "https://sovra.example/vct/adult-status/1";

export interface MachineAccount {
  tenantId: string;
  token: string;
}

export function psql(sql: string): string {
  const out = execFileSync(
    "docker",
    [
      "exec",
      "-e",
      `PGPASSWORD=${DB_PASSWORD}`,
      DB_CONTAINER,
      "psql",
      "-U",
      "sovra",
      "-d",
      "sovra",
      "-v",
      "ON_ERROR_STOP=1",
      "-tA",
      "-c",
      sql,
    ],
    { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] },
  ) as string;
  return out.trim().split("\n")[0]!.trim();
}

export function mintAccount(name: string, roles: string): MachineAccount {
  const tenantId = psql("SELECT id FROM tenant WHERE slug = 'sovra-demo';");
  if (!tenantId) {
    throw new Error("sovra-demo tenant missing (is the compose stack up?)");
  }
  const token = `sovra_test_${randomBytes(32).toString("base64url")}`;
  const prefix = token.slice("sovra_test_".length, "sovra_test_".length + 8);
  const digest = createHash("sha256").update(token, "utf-8").digest("hex");
  psql(
    `INSERT INTO service_account (tenant_id, name, token_prefix, token_hash, roles) ` +
      `VALUES ('${tenantId}', '${name}', '${prefix}', decode('${digest}', 'hex'), '{${roles}}');`,
  );
  return { tenantId, token };
}

export function clientFor(token: string): SovraClient {
  return new SovraClient({ baseUrl: BASE, token });
}

// ---------------------------------------------------------------------------
// Test-only P-256 holder keys and ES256 proofs, mirroring the
// server's proof formats. Never ships in the SDK's API.
// ---------------------------------------------------------------------------

export function generateHolder(): {
  privateKey: import("node:crypto").KeyObject;
  jwk: { kty: string; crv: string; x: string; y: string };
} {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const exported = publicKey.export({ format: "jwk" });
  return {
    privateKey,
    jwk: {
      kty: "EC",
      crv: "P-256",
      x: exported.x as string,
      y: exported.y as string,
    },
  };
}

export function thumbprint(
  holder: Pick<ReturnType<typeof generateHolder>, "jwk">,
): string {
  const canonical =
    `{"crv":"P-256","kty":"EC","x":"${holder.jwk.x}","y":"${holder.jwk.y}"}`;
  return createHash("sha256").update(canonical, "utf-8").digest("base64url");
}

/** ES256 JWS (raw R||S) over an arbitrary message. */
export function proofOver(
  holder: ReturnType<typeof generateHolder>,
  message: string,
): string {
  const header = Buffer.from('{"alg":"ES256"}', "utf-8").toString("base64url");
  const payload = Buffer.from(message, "utf-8").toString("base64url");
  const data = Buffer.from(`${header}.${payload}`, "ascii");
  const sig = sign("sha256", data, {
    key: holder.privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${header}.${payload}.${sig.toString("base64url")}`;
}

export function issuanceProof(
  holder: ReturnType<typeof generateHolder>,
  key: string,
): string {
  return proofOver(
    holder,
    `sovra-issuance-proof/v1\n${key}\n${ADULT_VCT}\n${thumbprint(holder)}\nadultOver18=true`,
  );
}

export function randomHex(bytes: number): string {
  return randomBytes(bytes).toString("hex");
}

export function randomBase64Url(bytes: number): string {
  return randomBytes(bytes).toString("base64url");
}

// ---------------------------------------------------------------------------
// Synthetic verification plan (matches the backend's synthetic policy).
// ---------------------------------------------------------------------------

export const RP_ID = "https://rp.example/synth-shop";
export const AUDIENCE = "https://rp.example/synth-shop/callback";
export const PURPOSE = "synthetic age check at checkout";
export const POLICY_ID = "sovra-synthetic-policy/age-check";
export const POLICY_VERSION = "1";
export const SECTION_ID = "age_eligibility";

export function planWire(planId: string): Record<string, unknown> {
  return {
    plan_id: planId,
    requested_outcome: "age_over_18",
    candidate_issuer_id: ISSUER_ID,
    credential_type: ADULT_VCT,
    claim_paths: ["adultOver18"],
    evidence: [{ document_id: POLICY_ID, section_id: SECTION_ID }],
    policy_id: POLICY_ID,
    policy_version: POLICY_VERSION,
    recommendation: "CANDIDATE_ONLY",
  };
}

export function planHash(planId: string): string {
  const canonical = [
    "sovra-plan/v1",
    planId,
    "age_over_18",
    ISSUER_ID,
    ADULT_VCT,
    "adultOver18",
    `${POLICY_ID}#${SECTION_ID}`,
    POLICY_ID,
    POLICY_VERSION,
    "CANDIDATE_ONLY",
    "",
  ].join("\n");
  return createHash("sha256").update(canonical, "utf-8").digest("hex");
}
