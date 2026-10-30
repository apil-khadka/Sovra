import assert from "node:assert/strict";
import test from "node:test";
import {
  ADULT_VCT,
  ISSUER_ID,
  clientFor,
  generateHolder,
  issuanceProof,
  mintAccount,
} from "./live.js";
import {
  SovraClient,
  SovraError,
  mintIdempotencyKey,
  validIdempotencyKey,
} from "../index.js";

/**
 * Cross-cutting SDK guarantees (SOV-021): origin validation,
 * typed sanitized errors, idempotent replay, and ETag misses.
 * No network needed except where noted.
 */
test("originsValidateAtConstruction", () => {
  assert.throws(
    () => new SovraClient({ baseUrl: "http://example.com", token: "t" }),
    /https/,
  );
  assert.throws(() => new SovraClient({ baseUrl: "not-a-url)://", token: "t" }));
  assert.throws(
    () => new SovraClient({ baseUrl: "http://localhost:8080", token: " " }),
    /token/,
  );
  new SovraClient({ baseUrl: "http://localhost:8080/", token: "t" });
  new SovraClient({ baseUrl: "http://127.0.0.1:8080", token: "t" });
  new SovraClient({ baseUrl: "https://sovra.example", token: "t" });
  assert.equal(SovraClient.SUPPORTED_CONTRACT, "0.16.0");
});

test("idempotencyKeysMatchTheServerAlphabet", () => {
  assert.equal(validIdempotencyKey(mintIdempotencyKey()), true);
  assert.equal(validIdempotencyKey("has space"), false);
  assert.equal(validIdempotencyKey(undefined), false);
});

test("unauthorizedMapsToTypedSanitizedErrors", async () => {
  const account = mintAccount("ts-guarantee", "TENANT_MEMBER");
  const bad = clientFor("sovra_test_definitely-not-a-token");
  const member = clientFor(account.token);
  try {
    await bad.ops.whoami();
    assert.fail("expected a 401");
  } catch (e: unknown) {
    assert.ok(e instanceof SovraError);
    assert.equal(e.status, 401);
    assert.ok(!e.message.includes("definitely-not-a-token"));
    assert.ok(!String(e).includes("definitely-not-a-token"));
  }
  await assert.rejects(
    () => member.trust.proposals(),
    (e: unknown) => e instanceof SovraError && e.status === 403,
  );
});

test("idempotentIssuanceReplaysByteIdentically", async () => {
  const account = mintAccount("ts-idempotent", "ISSUER_OPS");
  const holder = generateHolder();
  const key = mintIdempotencyKey();
  const proof = issuanceProof(holder, key);
  const expires = new Date(Date.now() + 3600_000).toISOString();
  const client = clientFor(account.token);
  const args = {
    idempotencyKey: key,
    issuerId: ISSUER_ID,
    vct: ADULT_VCT,
    holderJwk: holder.jwk,
    holderProof: proof,
    claims: { adultOver18: true },
    expiresAt: expires,
  };
  const first = await client.issuance.issue(args);
  const replay = await client.issuance.issue(args);
  assert.equal(replay.credentialId, first.credentialId);
  assert.equal(replay.artifact, first.artifact);
  await assert.rejects(
    () =>
      client.issuance.issue({
        ...args,
        expiresAt: new Date(Date.now() + 7200_000).toISOString(),
      }),
    (e: unknown) => e instanceof SovraError && e.status === 409,
  );
});

test("conditionalReadsReport304AsEmpty", async () => {
  const account = mintAccount("ts-etag", "ISSUER_OPS");
  const client = clientFor(account.token);
  const fixture =
    "SOVRA-FIXTURE/v1\nname: Ana Example\ndocument_number: X1\n" +
    "date_of_birth: 1990-01-02\n";
  const stored = await client.vault.store(
    "https://issuer.example/ts-etag",
    "etag source",
    ["extraction-run"],
    Buffer.from(fixture, "utf-8"),
  );
  const grant = await client.vault.grant(
    stored.objectId,
    1,
    "service_account",
    undefined,
    "extraction-run",
    "ts-test",
    3600,
  );
  const run = await client.extraction.run(
    stored.objectId,
    1,
    grant.grantId,
    "extraction-run",
    "ts-test",
    "fixture-doc-v1",
  );
  const tagged = await client.getTagged(
    `/api/extraction/records/${run.recordId}`,
  );
  assert.ok(tagged);
  assert.equal(
    (tagged.value as { engineId: string }).engineId,
    "fixture-v1",
  );
  assert.ok(tagged.etag.length > 0);
  assert.equal(
    await client.extraction.get(run.recordId, tagged.etag),
    undefined,
  );
  // The review queue lists the new run under the pending posture.
  const queue = await client.extraction.list("pending", 50);
  assert.ok(queue.items.map((i) => i.recordId).includes(run.recordId));
});
