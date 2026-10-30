import assert from "node:assert/strict";
import test from "node:test";
import {
  ADULT_VCT,
  AUDIENCE,
  ISSUER_ID,
  POLICY_ID,
  POLICY_VERSION,
  PURPOSE,
  RP_ID,
  clientFor,
  generateHolder,
  issuanceProof,
  mintAccount,
  planHash,
  planWire,
  proofOver,
  randomBase64Url,
  randomHex,
  thumbprint,
} from "./live.js";
import {
  OpsResource,
  SovraError,
  mintIdempotencyKey,
} from "../index.js";

/** Issuer/RP quickstart (SOV-021): issue, consent, present, verify. */
test("issueConsentVerifyQuickstart", async () => {
  const issuer = mintAccount("ts-issuer", "ISSUER_OPS");
  const rp = mintAccount("ts-rp", "RP_CLIENT,TENANT_MEMBER");
  const holder = generateHolder();
  const tp = thumbprint(holder);
  const key = mintIdempotencyKey();
  const expires = new Date(Date.now() + 7200_000).toISOString();
  const issuerClient = clientFor(issuer.token);
  const rpClient = clientFor(rp.token);

  const issued = await issuerClient.issuance.issue({
    idempotencyKey: key,
    issuerId: ISSUER_ID,
    vct: ADULT_VCT,
    holderJwk: holder.jwk,
    holderProof: issuanceProof(holder, key),
    claims: { adultOver18: true },
    expiresAt: expires,
  });
  assert.equal(issued.status, "VALID");
  assert.equal(
    (await issuerClient.issuance.status(issued.credentialId)).status,
    "VALID",
  );
  assert.equal(
    (await issuerClient.issuance.get(issued.credentialId)).credentialId,
    issued.credentialId,
  );

  const planId = `pln_ts_${randomHex(12)}`;
  const created = await rpClient.consent.create({
    rpId: RP_ID,
    audience: AUDIENCE,
    purpose: PURPOSE,
    credentialId: issued.credentialId,
    claims: { adultOver18: true },
    plan: planWire(planId),
    policyId: POLICY_ID,
    policyVersion: POLICY_VERSION,
    planHash: planHash(planId),
    challenge: randomBase64Url(24),
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
  });
  assert.equal(created.state, "PENDING");
  const review = await rpClient.consent.review(created.requestId);
  assert.ok(review);
  const consentMessage =
    `sovra-consent/v1\n${review.requestId}\napprove\n${review.rpId}\n` +
    `${review.audience}\n${review.purpose}\nadultOver18=true\n` +
    `${review.planHash}\n${review.challenge}\n${review.expiresAt}\n${review.holderThumbprint}`;
  const decided = await rpClient.consent.decide(
    created.requestId,
    "approve",
    holder.jwk,
    proofOver(holder, consentMessage),
  );
  assert.equal(decided.state, "VERIFIED");
  const presentation = await rpClient.consent.presentation(created.requestId);
  assert.equal(presentation.presentation.split(".").length, 3);

  const nonce = mintIdempotencyKey();
  const bindingProof = proofOver(
    holder,
    `sovra-presentation/v1\n${created.requestId}\n${nonce}\n${AUDIENCE}\n${tp}`,
  );
  const decision = await rpClient.verification.verify(
    created.requestId,
    nonce,
    AUDIENCE,
    holder.jwk,
    bindingProof,
  );
  assert.equal(decision.outcome, "ACCEPTED");
  const replay = await rpClient.verification.verify(
    created.requestId,
    nonce,
    AUDIENCE,
    holder.jwk,
    bindingProof,
  );
  assert.equal(replay.decisionId, decision.decisionId);
  assert.equal(
    (await rpClient.verification.get(decision.decisionId))?.outcome,
    "ACCEPTED",
  );
});

test("issuanceRejectsUnreviewedClaims", async () => {
  const issuer = mintAccount("ts-neg", "ISSUER_OPS");
  const holder = generateHolder();
  const key = mintIdempotencyKey();
  const client = clientFor(issuer.token);
  await assert.rejects(
    () =>
      client.issuance.issue({
        idempotencyKey: key,
        issuerId: ISSUER_ID,
        vct: ADULT_VCT,
        holderJwk: holder.jwk,
        holderProof: issuanceProof(holder, key),
        claims: { adultOver18: true, smuggled: "x" },
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      }),
    (e: unknown) => e instanceof SovraError && e.status === 400,
  );
});

/** Credential lifecycle: create, rotate, revoke — tokens work once shown. */
test("serviceAccountLifecycle", async () => {
  const admin = mintAccount("ts-auth-admin", "TRUST_ADMIN");
  const adminClient = clientFor(admin.token);
  const created = await adminClient.auth.create("ts-managed", [
    "TENANT_MEMBER",
  ]);
  assert.ok(created.token.startsWith("sovra_test_"));
  const ids = (await adminClient.auth.list()).map((a) => a.id);
  assert.ok(ids.includes(created.id));
  assert.equal((await adminClient.auth.get(created.id)).name, "ts-managed");
  assert.equal((await clientFor(created.token).ops.whoami()).name, "ts-managed");

  const rotated = await adminClient.auth.rotate(created.id);
  assert.notEqual(rotated.token, created.token);
  await assert.rejects(
    () => clientFor(created.token).ops.whoami(),
    (e: unknown) => e instanceof SovraError && e.status === 401,
  );
  assert.equal((await clientFor(rotated.token).ops.whoami()).name, "ts-managed");

  const revoked = await adminClient.auth.revoke(created.id);
  assert.equal(revoked.revoked, true);
  await assert.rejects(
    () => clientFor(rotated.token).ops.whoami(),
    (e: unknown) => e instanceof SovraError && e.status === 401,
  );
});

/** Ops quickstart: health, readiness, snapshot, identity, alerts, audit. */
test("opsQuickstart", async () => {
  const account = mintAccount("ts-ops", "ISSUER_OPS,AUDIT_READER");
  const client = clientFor(account.token);
  assert.equal((await client.ops.health()).status, "UP");
  const readiness = await client.ops.readiness();
  assert.equal(readiness.status, "READY");
  assert.ok(readiness.checks.length > 0);
  assert.ok((await client.ops.whoami()).roles.includes("ISSUER_OPS"));
  const snapshot = await client.ops.snapshot();
  assert.ok(snapshot && snapshot.version > 0 && snapshot.issuers.length > 0);
  assert.ok((await client.ops.alerts()) !== null);
  assert.ok((await client.ops.audit(5)) !== null);
});

test("auditCursorPassesThroughOpaquely", async () => {
  const account = mintAccount("ts-audit", "AUDIT_READER");
  const client = clientFor(account.token);
  const first = await client.ops.audit(2);
  assert.ok(first.length <= 2);
  if (first.length > 0) {
    const last = first[first.length - 1]!;
    const next = await client.ops.audit(2, OpsResource.cursorFor(last));
    assert.ok(next !== null);
    for (const row of next) {
      assert.notEqual(row.id, last.id);
    }
  }
});

/** Vault quickstart: store, grant, metadata, purpose-bound read. */
test("vaultStoreGrantReadRoundTrip", async () => {
  const ops = mintAccount("ts-vault", "ISSUER_OPS");
  const reader = mintAccount("ts-reader", "TENANT_MEMBER");
  const content = Buffer.from("ts vault bytes", "utf-8");
  const opsClient = clientFor(ops.token);
  const readerClient = clientFor(reader.token);

  const stored = await opsClient.vault.store(
    "https://issuer.example/ts-vault",
    "ts object",
    ["ts-review"],
    content,
  );
  assert.equal(stored.version, 1);
  assert.equal(
    (await opsClient.vault.metadata(stored.objectId)).versions.length,
    1,
  );
  const readerId = (await readerClient.ops.whoami()).accountId;
  const grant = await opsClient.vault.grant(
    stored.objectId,
    1,
    "service_account",
    readerId,
    "ts-review",
    "ts-desk",
    3600,
  );
  assert.equal(grant.revoked, false);
  const read = await readerClient.vault.read(
    stored.objectId,
    1,
    grant.grantId,
    "ts-review",
    "ts-desk",
  );
  assert.ok(Buffer.from(read.contentBase64, "base64").equals(content));
  await assert.rejects(
    () =>
      readerClient.vault.read(
        stored.objectId,
        1,
        grant.grantId,
        "other-purpose",
        "ts-desk",
      ),
    (e: unknown) => e instanceof SovraError && e.status === 403,
  );
});

/** Enrollment + custody quickstart: case to approval, report, recover. */
test("enrollmentCustodyQuickstart", async () => {
  const maker = mintAccount("ts-enr-maker", "ISSUER_OPS");
  const checker = mintAccount("ts-enr-checker", "ISSUER_OPS");
  const admin = mintAccount("ts-enr-admin", "TRUST_ADMIN");
  const holder = generateHolder();
  const fresh = generateHolder();
  const makerClient = clientFor(maker.token);
  const checkerClient = clientFor(checker.token);
  const adminClient = clientFor(admin.token);

  const stored = await makerClient.vault.store(
    "https://issuer.example/ts-enrollment",
    "ts enrollment source",
    ["extraction-run"],
    Buffer.from(
      "SOVRA-FIXTURE/v1\nname: Ana Example\ndocument_number: X1234567\n" +
        "date_of_birth: 1990-01-02\ncountry: NL\n",
      "utf-8",
    ),
  );
  const grant = await makerClient.vault.grant(
    stored.objectId,
    1,
    "service_account",
    undefined,
    "extraction-run",
    "ts-test",
    3600,
  );
  const run = await makerClient.extraction.run(
    stored.objectId,
    1,
    grant.grantId,
    "extraction-run",
    "ts-test",
    "fixture-doc-v1",
  );
  await makerClient.extraction.approve(run.recordId, 1);

  const created = await makerClient.enrollment.create(
    stored.objectId,
    run.recordId,
    holder.jwk,
  );
  assert.equal(created.state, "PENDING");
  await makerClient.enrollment.submit(created.enrollmentId);
  const decided = await checkerClient.enrollment.decide(
    created.enrollmentId,
    1,
    "approve",
    proofOver(holder, `enrollment-binding\n${created.enrollmentId}\n1`),
  );
  assert.equal(decided.state, "APPROVED");
  const eligibility = await makerClient.enrollment.eligibility(
    created.enrollmentId,
  );
  assert.equal(eligibility.eligible, true);
  assert.equal(eligibility.claims["adultOver18"], "true");

  const reported = await makerClient.custody.report(
    thumbprint(holder),
    "loss",
  );
  assert.equal(reported.revokedCredentials, 0);
  const recovered = await adminClient.custody.recover(
    reported.recoveryId,
    fresh.jwk,
    proofOver(
      fresh,
      `holder-recovery\n${reported.recoveryId}\n${thumbprint(fresh)}`,
    ),
  );
  assert.equal(recovered.newThumbprint, thumbprint(fresh));
  const key = await makerClient.custody.get(reported.keyId);
  assert.equal(key?.status, "COMPROMISED");
  assert.equal(key?.recoveries.length, 1);
  // The case queue lists the approved case with current eligibility.
  const queue = await makerClient.enrollment.list("approved", 50);
  assert.ok(queue.items.map((i) => i.enrollmentId).includes(created.enrollmentId));
});

/** Trust lifecycle: queue, onboard, approve, activate — with the two-person rule. */
test("trustAdminsOnboardThroughMakerChecker", async () => {
  const maker = mintAccount("ts-maker", "TRUST_ADMIN");
  const checker = mintAccount("ts-checker", "TRUST_ADMIN");
  const makerClient = clientFor(maker.token);
  const checkerClient = clientFor(checker.token);

  const before = await makerClient.trust.proposals();
  assert.ok(before !== null);
  const current = await makerClient.ops.snapshot();
  assert.ok(current && current.issuers.length > 0);

  // Read-modify-write: carry every authorized issuer and policy
  // forward so the test never evicts the shared stack's issuers.
  const carried: Record<string, unknown>[] = [];
  for (const existing of current.issuers) {
    // Skip our own test issuer id; a fresh row is appended below so
    // repeated runs never accumulate duplicate entries.
    if (existing.issuerId === "ts-onboard-issuer") {
      continue;
    }
    carried.push({
      issuerId: existing.issuerId,
      displayName: existing.displayName,
      scope: existing.scope,
      credentialTypes: existing.credentialTypes,
      keyId: existing.keyId,
      keyVersion: existing.keyVersion,
      publicKeyJwk: existing.publicKeyJwk,
      validFrom: existing.validFrom,
      validThrough: existing.validThrough,
      status: existing.status,
    });
  }
  const policies = current.policies.map((p) => ({
    rpId: p.rpId,
    purpose: p.purpose,
    allowedTypes: p.allowedTypes,
    maxAssurance: p.maxAssurance,
  }));
  const keyId = `ts-${mintIdempotencyKey().slice(0, 8)}`;
  carried.push({
    issuerId: "ts-onboard-issuer",
    displayName: "TS onboard issuer",
    scope: "adult-status",
    credentialTypes: [ADULT_VCT],
    keyId,
    keyVersion: 1,
    publicKeyJwk: {
      kty: "EC",
      crv: "P-256",
      kid: keyId,
      x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    },
    validFrom: new Date(Date.now() - 60_000).toISOString(),
    validThrough: new Date(Date.now() + 3600_000).toISOString(),
    status: "ACTIVE",
  });
  const proposed = await makerClient.trust.propose(
    carried,
    policies,
    "ts onboarding test",
  );
  assert.ok(Number(proposed.version) > current.version);

  const queue = await checkerClient.trust.proposals();
  assert.ok(queue.map((p) => p.proposalId).includes(proposed.proposalId));

  await assert.rejects(
    () => makerClient.trust.approve(proposed.proposalId),
    (e: unknown) => e instanceof SovraError && e.status === 403,
  );

  const approved = await checkerClient.trust.approve(proposed.proposalId);
  assert.equal(approved.proposalId, proposed.proposalId);
  const activated = await checkerClient.trust.activate(Number(proposed.version));
  assert.equal(activated.version, proposed.version);
  assert.equal(
    (await makerClient.ops.snapshot())?.version,
    Number(proposed.version),
  );
});
