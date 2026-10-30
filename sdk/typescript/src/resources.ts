import type { SovraClient } from "./client.js";
import { SovraError, validIdempotencyKey } from "./errors.js";

/** Base class: every resource delegates transport to the root client. */
class Resource {
  constructor(protected readonly client: SovraClient) {}
}

// ---------------------------------------------------------------------------
// Ops
// ---------------------------------------------------------------------------

export interface SnapshotIssuer {
  issuerId: string;
  displayName: string;
  scope: string;
  credentialTypes: string[];
  keyId: string;
  keyVersion: number;
  publicKeyJwk: unknown;
  validFrom: string;
  validThrough: string;
  status: string;
}

export interface SnapshotPolicy {
  rpId: string;
  purpose: string;
  allowedTypes: string[];
  maxAssurance: string;
}

export interface TrustSnapshot {
  version: number;
  issuers: SnapshotIssuer[];
  policies: SnapshotPolicy[];
}

export interface Health {
  status: string;
  service: string;
  version: string;
}

export interface ReadinessCheck {
  name: string;
  status: string;
  code: string;
  detail: Record<string, unknown>;
  durationMs: number;
}

export interface ReadinessReport {
  status: string;
  checks: ReadinessCheck[];
}

export interface WhoAmI {
  accountId: string;
  tenantId: string;
  name: string;
  roles: string[];
}

export interface AuditEvent {
  id: string;
  occurredAt: string;
  actorType: string;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  decision: string;
  reasonCode: string;
  policyVersion: number;
  correlationId: string;
  detail: unknown;
}

export interface Alert {
  alert: string;
  severity: string;
  status: string;
  code: string;
  check: string;
  firstObservedAt: string;
  observedAt: string;
}

/** Operational reads: health, readiness, trust snapshot, audit, alerts, identity. */
export class OpsResource extends Resource {
  health(): Promise<Health> {
    return this.client.get("/api/health");
  }

  readiness(): Promise<ReadinessReport> {
    return this.client.get("/api/health/ready");
  }

  /** Active federation snapshot, or null when none is activated yet. */
  async snapshot(): Promise<TrustSnapshot | null> {
    try {
      return await this.client.get("/api/trust/snapshots/current");
    } catch (e: unknown) {
      if (e instanceof SovraError && e.status === 404) {
        return null;
      }
      throw e;
    }
  }

  whoami(): Promise<WhoAmI> {
    return this.client.get("/api/whoami");
  }

  /** Newest audit rows first; the cursor passes through opaquely. */
  audit(limit: number, cursor?: string): Promise<AuditEvent[]> {
    const path =
      `/api/audit/events?limit=${limit}` +
      (cursor === undefined ? "" : `&cursor=${encodeURIComponent(cursor)}`);
    return this.client.get(path);
  }

  /** Builds the next-page cursor from the last row of a page. */
  static cursorFor(last: AuditEvent): string {
    return Buffer.from(`${last.occurredAt}|${last.id}`, "utf-8").toString("base64url");
  }

  alerts(): Promise<Alert[]> {
    return this.client.get("/api/alerts");
  }
}

// ---------------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------------

export interface ProposalSummary {
  proposalId: string;
  version: number;
  state: string;
  proposedBy: string;
  approvedBy: string;
  createdAt: string;
}

export interface ProposeResult {
  version: string;
  proposalId: string;
}

export interface ApproveResult {
  proposalId: string;
  personVerified: string;
}

export interface ActivateResult {
  version: string;
}

export interface TrustKeyView {
  issuerId: string;
  keyId: string;
  keyVersion: number;
  status: string;
  revokedAt: string;
}

/** Trust review queue and key lifecycle (TRUST_ADMIN). */
export class TrustResource extends Resource {
  proposals(): Promise<ProposalSummary[]> {
    return this.client.get("/api/trust/proposals");
  }

  propose(
    issuers: Record<string, unknown>[],
    policies: Record<string, unknown>[],
    note?: string,
  ): Promise<ProposeResult> {
    return this.client.post("/api/trust/proposals", {
      issuers,
      policies,
      note: note ?? "",
    });
  }

  approve(proposalId: string): Promise<ApproveResult> {
    return this.client.post(`/api/trust/proposals/${proposalId}/approve`, {});
  }

  activate(version: number): Promise<ActivateResult> {
    return this.client.post(`/api/trust/snapshots/${version}/activate`, {});
  }

  registerKey(
    issuerId: string,
    keyId: string,
    keyVersion: number,
    publicKeyJwk: unknown,
  ): Promise<TrustKeyView> {
    return this.client.post("/api/trust/keys", {
      issuerId,
      keyId,
      keyVersion,
      publicKeyJwk,
    });
  }

  revokeKey(
    issuerId: string,
    keyId: string,
    keyVersion: number,
    reason: string,
  ): Promise<TrustKeyView> {
    return this.client.post("/api/trust/keys/revoke", {
      issuerId,
      keyId,
      keyVersion,
      reason,
    });
  }
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export interface ServiceAccount {
  id: string;
  name: string;
  roles: string[];
  revoked: boolean;
  expiresAt: string;
  createdAt: string;
}

export interface ServiceAccountWithToken extends ServiceAccount {
  token: string;
}

/** Application credential lifecycle (TRUST_ADMIN). Tokens appear once, in create/rotate bodies. */
export class AuthResource extends Resource {
  create(
    name: string,
    roles: string[],
    expiresAt?: string,
  ): Promise<ServiceAccountWithToken> {
    const body: Record<string, unknown> = { name, roles };
    if (expiresAt !== undefined) {
      body["expiresAt"] = expiresAt;
    }
    return this.client.post("/api/auth/service-accounts", body);
  }

  list(): Promise<ServiceAccount[]> {
    return this.client.get("/api/auth/service-accounts");
  }

  get(id: string): Promise<ServiceAccount> {
    return this.client.get(`/api/auth/service-accounts/${id}`);
  }

  rotate(id: string, expiresAt?: string): Promise<ServiceAccountWithToken> {
    const body: Record<string, unknown> = {};
    if (expiresAt !== undefined) {
      body["expiresAt"] = expiresAt;
    }
    return this.client.post(`/api/auth/service-accounts/${id}/rotate`, body);
  }

  /** Idempotent terminal revocation. */
  revoke(id: string): Promise<ServiceAccount> {
    return this.client.post(`/api/auth/service-accounts/${id}/revoke`, {});
  }
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

export interface IssuedCredential {
  credentialId: string;
  artifact: string;
  status: string;
  expiresAt: string;
  trustSnapshot: number;
}

export interface CredentialView {
  credentialId: string;
  issuerId: string;
  vct: string;
  keyRef: string;
  issuedAt: string;
  expiresAt: string;
  status: string;
  trustSnapshot: number;
}

export interface CredentialStatus {
  status: string;
  version: number;
  fetchedAt: string;
  maxAgeSeconds: number;
}

export interface RevokedCredential {
  credentialId: string;
  status: string;
}

export interface IssueArgs {
  idempotencyKey: string;
  issuerId: string;
  vct: string;
  holderJwk: unknown;
  holderProof: string;
  claims: Record<string, unknown>;
  expiresAt: string;
  enrollmentId?: string;
}

/**
 * Issuer-scoped credential issuance. The idempotency key makes
 * retries safe: resending the same key and request replays the
 * original response byte-for-byte instead of minting twice.
 */
export class IssuanceResource extends Resource {
  issue(args: IssueArgs): Promise<IssuedCredential> {
    if (!validIdempotencyKey(args.idempotencyKey)) {
      throw new Error("idempotency key is malformed");
    }
    const body: Record<string, unknown> = {
      issuerId: args.issuerId,
      vct: args.vct,
      holderJwk: args.holderJwk,
      holderProof: args.holderProof,
      claims: args.claims,
      expiresAt: args.expiresAt,
    };
    if (args.enrollmentId !== undefined) {
      body["enrollmentId"] = args.enrollmentId;
    }
    return this.client.post("/api/issuance/credentials", body, {
      "idempotency-key": args.idempotencyKey,
    });
  }

  get(credentialId: string): Promise<CredentialView> {
    return this.client.get(`/api/issuance/credentials/${credentialId}`);
  }

  status(credentialId: string): Promise<CredentialStatus> {
    return this.client.get(`/api/issuance/credentials/${credentialId}/status`);
  }

  revoke(credentialId: string): Promise<RevokedCredential> {
    return this.client.post(`/api/issuance/credentials/${credentialId}/revoke`, {});
  }

  jwks(): Promise<string> {
    return this.client.getText("/api/issuance/jwks.json");
  }
}

// ---------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------

export interface ConsentRequestView {
  requestId: string;
  rpId: string;
  audience: string;
  purpose: string;
  credentialId: string;
  claims: Record<string, unknown>;
  planHash: string;
  challenge: string;
  holderThumbprint: string;
  state: string;
  stateReason: string;
  createdAt: string;
  expiresAt: string;
  trustSnapshot: number;
}

export interface PresentationView {
  requestId: string;
  state: string;
  synthetic: boolean;
  profile: string;
  presentation: string;
  claims: Record<string, unknown>;
  expiresAt: string;
  trustSnapshot: number;
}

export interface CreateConsentArgs {
  rpId: string;
  audience: string;
  purpose: string;
  credentialId: string;
  claims: Record<string, unknown>;
  plan: Record<string, unknown>;
  policyId: string;
  policyVersion: string;
  planHash: string;
  challenge: string;
  expiresAt: string;
}

/** Consent-bound proof requests: RP creation, holder review/decision, presentation reads. */
export class ConsentResource extends Resource {
  create(args: CreateConsentArgs): Promise<ConsentRequestView> {
    return this.client.post("/api/consent/requests", { ...args });
  }

  review(requestId: string, ifNoneMatch?: string): Promise<ConsentRequestView | undefined> {
    return this.client.getOptional(`/api/consent/requests/${requestId}`, ifNoneMatch);
  }

  decide(
    requestId: string,
    decision: string,
    holderJwk: unknown,
    consentProof: string,
  ): Promise<ConsentRequestView> {
    return this.client.post(`/api/consent/requests/${requestId}/decision`, {
      decision,
      holderJwk,
      consentProof,
    });
  }

  presentation(requestId: string): Promise<PresentationView> {
    return this.client.get(`/api/consent/requests/${requestId}/presentation`);
  }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export interface Decision {
  decisionId: string;
  requestId: string;
  outcome: string;
  reasonCode: string;
  synthetic: boolean;
  profile: string;
  trustSnapshot: number;
  keyRef: string;
  statusVersion: number;
  decidedAt: string;
}

/**
 * Presentation verification. One decision per nonce: resending the
 * same nonce replays the stored response byte-for-byte, while the
 * same nonce with different content conflicts without rewriting.
 */
export class VerificationResource extends Resource {
  verify(
    requestId: string,
    nonce: string,
    audience: string,
    holderJwk: unknown,
    bindingProof: string,
  ): Promise<Decision> {
    return this.client.post("/api/verification/presentations", {
      requestId,
      nonce,
      audience,
      holderJwk,
      bindingProof,
    });
  }

  get(decisionId: string, ifNoneMatch?: string): Promise<Decision | undefined> {
    return this.client.getOptional(
      `/api/verification/decisions/${decisionId}`,
      ifNoneMatch,
    );
  }
}

// ---------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------

export interface StoredVersion {
  objectId: string;
  version: number;
}

export interface VersionMetadata {
  version: number;
  purposes: string[];
  kekVersion: number;
  status: string;
  contentSha256Hex: string;
  createdAt: string;
}

export interface ObjectMetadata {
  objectId: string;
  issuerId: string;
  displayName: string;
  versions: VersionMetadata[];
}

export interface GrantView {
  grantId: string;
  objectId: string;
  objectVersion: number;
  principalType: string;
  principalId: string;
  purpose: string;
  workload: string;
  revoked: boolean;
  expiresAt: string;
  createdAt: string;
}

export interface ReadView {
  objectId: string;
  version: number;
  contentSha256Hex: string;
  contentBase64: string;
}

export interface KekVersion {
  kekVersion: number;
}

export interface DeletedVersion {
  objectId: string;
  version: number;
  status: string;
}

/**
 * Encrypted vault: purpose-bound storage with grants. Uploads are
 * bounded server-side; reads need a live grant for the exact
 * purpose and workload.
 */
export class VaultResource extends Resource {
  store(
    issuerId: string,
    displayName: string | undefined,
    purposes: string[],
    content: Uint8Array | undefined,
  ): Promise<StoredVersion> {
    return this.client.post("/api/vault/objects", {
      issuerId,
      displayName: displayName ?? "",
      purposes,
      contentBase64: Buffer.from(content ?? new Uint8Array()).toString("base64"),
    });
  }

  storeVersion(
    objectId: string,
    purposes: string[],
    content: Uint8Array | undefined,
  ): Promise<StoredVersion> {
    return this.client.post(`/api/vault/objects/${objectId}/versions`, {
      purposes,
      contentBase64: Buffer.from(content ?? new Uint8Array()).toString("base64"),
    });
  }

  metadata(objectId: string): Promise<ObjectMetadata> {
    return this.client.get(`/api/vault/objects/${objectId}`);
  }

  read(
    objectId: string,
    version: number,
    grantId: string,
    purpose: string,
    workload: string,
  ): Promise<ReadView> {
    return this.client.post(
      `/api/vault/objects/${objectId}/versions/${version}/read`,
      { grantId, purpose, workload },
    );
  }

  grant(
    objectId: string,
    objectVersion: number,
    principalType: string | undefined,
    principalId: string | undefined,
    purpose: string,
    workload: string,
    ttlSeconds: number,
  ): Promise<GrantView> {
    const body: Record<string, unknown> = {
      objectId,
      objectVersion,
      purpose,
      workload,
      ttlSeconds,
    };
    if (principalType !== undefined) {
      body["principalType"] = principalType;
    }
    if (principalId !== undefined) {
      body["principalId"] = principalId;
    }
    return this.client.post("/api/vault/grants", body);
  }

  revokeGrant(grantId: string): Promise<GrantView> {
    return this.client.post(`/api/vault/grants/${grantId}/revoke`, {});
  }

  rotateKek(): Promise<KekVersion> {
    return this.client.post("/api/vault/keys/rotate", {});
  }

  deleteVersion(objectId: string, version: number): Promise<DeletedVersion> {
    return this.client.post(
      `/api/vault/objects/${objectId}/versions/${version}/delete`,
      {},
    );
  }
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

export interface Admitted {
  admissionId: string;
  objectId: string;
  status: string;
  actualType: string;
  sizeBytes: number;
}

export interface AdmissionView {
  admissionId: string;
  objectId: string;
  status: string;
  claimedType: string;
  actualType: string;
  sizeBytes: number;
  contentSha256Hex: string;
  verdict: string;
  imageWidth: number | null;
  imageHeight: number | null;
  scannedAt: string;
  createdAt: string;
}

export interface Promoted {
  admissionId: string;
  objectId: string;
  version: number;
}

/** Hostile-image quarantine: sealed admission, isolated verdicts, clean promotion. */
export class QuarantineResource extends Resource {
  admit(
    content: Uint8Array | undefined,
    claimedType: string,
    issuerId: string,
  ): Promise<Admitted> {
    return this.client.post("/api/quarantine/admissions", {
      contentBase64: Buffer.from(content ?? new Uint8Array()).toString("base64"),
      claimedType,
      issuerId,
    });
  }

  /** Metadata-only: no endpoint serves quarantine bytes. */
  get(admissionId: string): Promise<AdmissionView> {
    return this.client.get(`/api/quarantine/admissions/${admissionId}`);
  }

  promote(
    admissionId: string,
    grantId: string,
    purpose: string,
    workload: string,
    purposes?: string[],
    displayName?: string,
  ): Promise<Promoted> {
    const body: Record<string, unknown> = { grantId, purpose, workload };
    if (purposes !== undefined) {
      body["purposes"] = purposes;
    }
    if (displayName !== undefined) {
      body["displayName"] = displayName;
    }
    return this.client.post(
      `/api/quarantine/admissions/${admissionId}/promote`,
      body,
    );
  }
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

export interface RunResult {
  recordId: string;
  revision: number;
  sourceDigestHex: string;
}

export interface CorrectionResult {
  recordId: string;
  revision: number;
}

export interface ApprovalResult {
  recordId: string;
  approvedRevision: number;
}

export interface RecordSummary {
  recordId: string;
  vaultObjectId: string;
  objectVersion: number;
  engineId: string;
  schemaId: string;
  approvedRevision: number | null;
  latestRevision: number;
  createdBy: string;
  createdAt: string;
}

export interface RecordPage {
  items: RecordSummary[];
  nextCursor: string | null;
}

export interface RevisionView {
  revNo: number;
  observed: Record<string, string>;
  normalized: Record<string, string>;
  canonicalDigests: Record<string, string>;
  exactDigests: Record<string, string>;
  confidence: number;
  supersedes: number | null;
  createdBy: string;
}

export interface ExtractionRecordView {
  recordId: string;
  vaultObjectId: string;
  objectVersion: number;
  sourceDigestHex: string;
  engineId: string;
  schemaId: string;
  normalizerId: string;
  canonId: string;
  approvedRevision: number | null;
  revisions: RevisionView[];
}

/**
 * Local extraction runs with protected digests and provenance.
 * Digests are integrity references inside authorized reads; no
 * call resolves rows by digest.
 */
export class ExtractionResource extends Resource {
  run(
    vaultObjectId: string,
    objectVersion: number,
    grantId: string,
    purpose: string,
    workload: string,
    schemaId: string,
  ): Promise<RunResult> {
    return this.client.post("/api/extraction/records", {
      vaultObjectId,
      objectVersion,
      grantId,
      purpose,
      workload,
      schemaId,
    });
  }

  get(recordId: string, ifNoneMatch?: string): Promise<ExtractionRecordView | undefined> {
    return this.client.getOptional(
      `/api/extraction/records/${recordId}`,
      ifNoneMatch,
    );
  }

  /** Review queue: state in all/pending/stale/approved, keyset-paged. */
  list(state: string | undefined, limit: number, cursor?: string): Promise<RecordPage> {
    let path = `/api/extraction/records?limit=${limit}`;
    if (state !== undefined) {
      path += `&state=${encodeURIComponent(state)}`;
    }
    if (cursor !== undefined) {
      path += `&cursor=${encodeURIComponent(cursor)}`;
    }
    return this.client.get(path);
  }

  correct(
    recordId: string,
    fields: Record<string, string>,
    confidence: number,
  ): Promise<CorrectionResult> {
    return this.client.post(`/api/extraction/records/${recordId}/revisions`, {
      fields,
      confidence,
    });
  }

  approve(recordId: string, revision: number): Promise<ApprovalResult> {
    return this.client.post(`/api/extraction/records/${recordId}/approval`, {
      revision,
    });
  }
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

export interface EnrollmentCreated {
  enrollmentId: string;
  subjectRef: string;
  state: string;
}

export interface EnrollmentState {
  enrollmentId: string;
  state: string;
}

export interface EnrollmentDecision {
  enrollmentId: string;
  state: string;
  boundRevision: number;
}

export interface Eligibility {
  enrollmentId: string;
  eligible: boolean;
  reason: string;
  claims: Record<string, string>;
}

export interface EnrollmentReview {
  revision: number;
  decision: string;
  bindingProofOk: boolean;
  reviewer: string;
}

export interface EnrollmentSummary {
  enrollmentId: string;
  subjectRef: string;
  vaultObjectId: string;
  extractionRecordId: string;
  boundRevision: number;
  state: string;
  createdBy: string;
  decidedBy: string;
  eligible: boolean;
  eligibilityReason: string;
  createdAt: string;
}

export interface EnrollmentPage {
  items: EnrollmentSummary[];
  nextCursor: string | null;
}

export interface EnrollmentView {
  enrollmentId: string;
  subjectRef: string;
  vaultObjectId: string;
  extractionRecordId: string;
  boundRevision: number;
  state: string;
  createdBy: string;
  decidedBy: string;
  eligible: boolean;
  eligibilityReason: string;
  reviews: EnrollmentReview[];
}

/**
 * Enrollment review with maker/checker separation. Approvals pin
 * the current extraction head; eligibility answers the issuance
 * gate with reviewed claims only.
 */
export class EnrollmentResource extends Resource {
  create(
    vaultObjectId: string,
    extractionRecordId: string,
    holderJwk: unknown,
  ): Promise<EnrollmentCreated> {
    return this.client.post("/api/enrollments", {
      vaultObjectId,
      extractionRecordId,
      holderJwk,
    });
  }

  submit(enrollmentId: string): Promise<EnrollmentState> {
    return this.client.post(`/api/enrollments/${enrollmentId}/submit`, {});
  }

  decide(
    enrollmentId: string,
    revision: number,
    decision: string,
    bindingProof?: string,
  ): Promise<EnrollmentDecision> {
    const body: Record<string, unknown> = { revision, decision };
    if (bindingProof !== undefined) {
      body["bindingProof"] = bindingProof;
    }
    return this.client.post(`/api/enrollments/${enrollmentId}/decision`, body);
  }

  get(enrollmentId: string, ifNoneMatch?: string): Promise<EnrollmentView | undefined> {
    return this.client.getOptional(`/api/enrollments/${enrollmentId}`, ifNoneMatch);
  }

  /** Case queue: state in all/pending/in_review/approved/rejected, keyset-paged. */
  list(state: string | undefined, limit: number, cursor?: string): Promise<EnrollmentPage> {
    let path = `/api/enrollments?limit=${limit}`;
    if (state !== undefined) {
      path += `&state=${encodeURIComponent(state)}`;
    }
    if (cursor !== undefined) {
      path += `&cursor=${encodeURIComponent(cursor)}`;
    }
    return this.client.get(path);
  }

  eligibility(enrollmentId: string): Promise<Eligibility> {
    return this.client.get(`/api/enrollments/${enrollmentId}/eligibility`);
  }
}

// ---------------------------------------------------------------------------
// Custody
// ---------------------------------------------------------------------------

export interface KeyReported {
  keyId: string;
  recoveryId: string;
  thumbprint: string;
  revokedCredentials: number;
}

export interface KeyRecovered {
  recoveryId: string;
  newThumbprint: string;
}

export interface RecoveryView {
  recoveryId: string;
  reason: string;
  state: string;
  newThumbprint: string;
}

export interface HolderKeyView {
  keyId: string;
  enrollmentId: string;
  thumbprint: string;
  status: string;
  createdBy: string;
  recoveries: RecoveryView[];
}

/**
 * Holder key custody: loss reports end a key's authority at once;
 * recovery activates a fresh proven key. Reads stay metadata-only.
 */
export class CustodyResource extends Resource {
  report(thumbprint: string, reason: string): Promise<KeyReported> {
    return this.client.post("/api/holder-keys/report", { thumbprint, reason });
  }

  recover(
    recoveryId: string,
    newHolderJwk: unknown,
    newKeyProof?: string,
  ): Promise<KeyRecovered> {
    const body: Record<string, unknown> = { recoveryId, newHolderJwk };
    if (newKeyProof !== undefined) {
      body["newKeyProof"] = newKeyProof;
    }
    return this.client.post("/api/holder-keys/recover", body);
  }

  get(keyId: string, ifNoneMatch?: string): Promise<HolderKeyView | undefined> {
    return this.client.getOptional(`/api/holder-keys/${keyId}`, ifNoneMatch);
  }
}
