package dev.sovra.extraction;

import dev.sovra.audit.AuditService;
import dev.sovra.audit.AuditedAuthorizer;
import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ResourceRef;
import dev.sovra.vault.VaultService;
import dev.sovra.web.KeysetCursor;
import java.math.BigDecimal;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

/**
 * Local extraction runs with protected digests and immutable
 * revisions (SOV-018, FR-36/38). Reads source bytes through the
 * vault grant path, runs the profile engine, normalizes fields,
 * and stores per-field canonical/exact digests. Corrections append
 * revisions; approvals pin the current revision explicitly, so a
 * stale approval can never silently authorize a newer run.
 */
@Service
public class ExtractionService {

  private final AuthorizationService authz;
  private final AuditService audit;
  private final VaultService vault;
  private final ExtractionEngine engine;
  private final JdbcTemplate tenant;
  private final ObjectMapper mapper;

  public ExtractionService(
      AuthorizationService authz,
      AuditService audit,
      VaultService vault,
      ExtractionEngine engine,
      JdbcTemplate tenantJdbcTemplate,
      ObjectMapper mapper) {
    this.authz = authz;
    this.audit = audit;
    this.vault = vault;
    this.engine = engine;
    this.tenant = tenantJdbcTemplate;
    this.mapper = mapper;
  }

  public record RunResult(UUID recordId, int revision, String sourceDigestHex) {}

  public record CorrectionResult(UUID recordId, int revision) {}

  public record ApprovalResult(UUID recordId, int approvedRevision) {}

  public record RevisionView(
      int revNo,
      Map<String, String> observed,
      Map<String, String> normalized,
      Map<String, String> canonicalDigestHex,
      Map<String, String> exactDigestHex,
      BigDecimal confidence,
      Integer supersedes,
      String createdBy) {}

  public record RecordView(
      UUID recordId,
      UUID vaultObjectId,
      int objectVersion,
      String sourceDigestHex,
      String engineId,
      String schemaId,
      String normalizerId,
      String canonId,
      Integer approvedRevision,
      List<RevisionView> revisions) {}

  public record RecordSummary(
      UUID recordId,
      UUID vaultObjectId,
      int objectVersion,
      String engineId,
      String schemaId,
      Integer approvedRevision,
      int latestRevision,
      String createdBy,
      String createdAt) {}

  public record RecordPage(List<RecordSummary> items, String nextCursor) {}

  /**
   * Review queue (SOV-023): newest records first, keyset-paged.
   * State filters the approval posture — {@code pending} (never
   * approved), {@code stale} (approved below the head), {@code
   * approved} (any approval), {@code all} default. Audited as one
   * read; summaries carry no field values or digests.
   */
  @Transactional(noRollbackFor = ForbiddenException.class)
  public RecordPage listRecords(
      ServiceAccountPrincipal caller, String state, int limit, String cursor) {
    Decision decision =
        require(caller, Action.EXTRACTION_READ, "extraction-record", "list");
    String posture = state == null || state.isBlank() ? "all" : state.strip().toLowerCase();
    String filter =
        switch (posture) {
          case "all" -> "";
          case "pending" -> " AND r.approved_revision IS NULL";
          case "approved" -> " AND r.approved_revision IS NOT NULL";
          case "stale" -> " AND r.approved_revision IS NOT NULL"
              + " AND r.approved_revision < COALESCE(m.max_rev, 0)";
          default -> throw new ExtractionInvalidException("unknown queue state");
        };
    int page = Math.min(Math.max(limit, 1), 200);
    KeysetCursor position = null;
    if (cursor != null && !cursor.isBlank()) {
      try {
        position = KeysetCursor.decode(cursor);
      } catch (IllegalArgumentException e) {
        throw new ExtractionInvalidException("malformed list cursor");
      }
    }
    String keyset = position == null
        ? ""
        : " AND (r.created_at < ? OR (r.created_at = ? AND r.id < ?))";
    List<RecordSummary> items =
        tenant.query(
            "SELECT r.id, r.vault_object_id, r.object_version, r.engine_id, r.schema_id,"
                + " r.approved_revision, COALESCE(m.max_rev, 0) AS latest_rev, r.created_by,"
                + " r.created_at FROM extraction_record r LEFT JOIN (SELECT record_id,"
                + " MAX(rev_no) AS max_rev FROM extraction_revision GROUP BY record_id) m"
                + " ON m.record_id = r.id WHERE r.tenant_id = ?" + filter + keyset
                + " ORDER BY r.created_at DESC, r.id DESC LIMIT ?",
            (rs, n) -> new RecordSummary(
                rs.getObject("id", UUID.class),
                rs.getObject("vault_object_id", UUID.class),
                rs.getInt("object_version"),
                rs.getString("engine_id"),
                rs.getString("schema_id"),
                rs.getObject("approved_revision", Integer.class),
                rs.getInt("latest_rev"),
                rs.getString("created_by"),
                rs.getTimestamp("created_at").toInstant().toString()),
            keysetArgs(caller.tenantId(), position, page + 1));
    String next = null;
    List<RecordSummary> shown = items;
    if (items.size() > page) {
      shown = items.subList(0, page);
      RecordSummary last = shown.get(shown.size() - 1);
      next = KeysetCursor.encode(last.createdAt(), last.recordId().toString());
    }
    audit.record(
        caller,
        Action.EXTRACTION_READ,
        ResourceRef.tenantScoped("extraction-record", "list", caller.tenantId()),
        decision,
        "",
        Map.of("state", posture, "count", String.valueOf(shown.size())));
    return new RecordPage(List.copyOf(shown), next);
  }

  private Object[] keysetArgs(UUID tenantId, KeysetCursor position, int limit) {
    if (position == null) {
      return new Object[] {tenantId, limit};
    }
    java.sql.Timestamp at = java.sql.Timestamp.from(position.createdAt());
    return new Object[] {tenantId, at, at, position.id(), limit};
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public RunResult extract(
      ServiceAccountPrincipal caller,
      UUID objectId,
      int version,
      UUID grantId,
      String purpose,
      String workload,
      String schemaId) {
    Decision decision =
        require(caller, Action.EXTRACTION_RUN, "extraction-record", objectId.toString());
    if (schemaId == null || schemaId.isBlank()) {
      throw new ExtractionInvalidException("schema is required");
    }
    VaultService.ReadResult source = vault.read(caller, objectId, version, grantId,
        purpose == null ? "" : purpose, workload == null ? "" : workload);
    ExtractionOutcome outcome = engine.run(source.content(), schemaId.strip());
    byte[] sourceDigest = FieldDigests.sha256(source.content());
    UUID recordId = UUID.randomUUID();
    try {
      tenant.update(
          "INSERT INTO extraction_record (id, tenant_id, vault_object_id, object_version,"
              + " source_digest, engine_id, schema_id, normalizer_id, canon_id, created_by)"
              + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          recordId,
          caller.tenantId(),
          objectId,
          version,
          sourceDigest,
          engine.engineId(),
          schemaId.strip(),
          FieldNormalizer.NORMALIZER_ID,
          FieldDigests.CANON_ID,
          caller.name());
    } catch (DuplicateKeyException e) {
      throw new ExtractionConflictException("extraction already exists for this source");
    }
    insertRevision(caller, recordId, 1, null, outcome.observed(), outcome.confidence());
    audit.record(
        caller,
        Action.EXTRACTION_RUN,
        ResourceRef.tenantScoped("extraction-record", recordId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of(
            "revision", "1",
            "engine", engine.engineId(),
            "schema", schemaId.strip(),
            "source", HexFormat.of().formatHex(sourceDigest)));
    return new RunResult(recordId, 1, HexFormat.of().formatHex(sourceDigest));
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public CorrectionResult correct(
      ServiceAccountPrincipal caller,
      UUID recordId,
      Map<String, String> fields,
      double confidence) {
    Decision decision =
        require(caller, Action.EXTRACTION_CORRECT, "extraction-record", recordId.toString());
    RecordRow record = recordRow(recordId);
    if (fields == null || fields.isEmpty()) {
      throw new ExtractionInvalidException("correction needs at least one field");
    }
    for (Map.Entry<String, String> field : fields.entrySet()) {
      if (field.getKey() == null
          || field.getKey().isBlank()
          || field.getValue() == null
          || field.getValue().isEmpty()) {
        throw new ExtractionInvalidException("correction fields must be non-empty");
      }
    }
    if (!(confidence >= 0 && confidence <= 1)) {
      throw new ExtractionInvalidException("confidence must be 0..1");
    }
    int revNo = record.maxRev + 1;
    insertRevision(caller, recordId, revNo, record.maxRev, fields, confidence);
    audit.record(
        caller,
        Action.EXTRACTION_CORRECT,
        ResourceRef.tenantScoped("extraction-record", recordId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("revision", String.valueOf(revNo)));
    return new CorrectionResult(recordId, revNo);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public ApprovalResult approve(
      ServiceAccountPrincipal caller, UUID recordId, int revision) {
    Decision decision =
        require(caller, Action.EXTRACTION_APPROVE, "extraction-record", recordId.toString());
    RecordRow record = recordRow(recordId);
    if (revision <= 0 || revision > record.maxRev) {
      throw new ExtractionInvalidException("unknown revision");
    }
    if (revision != record.maxRev) {
      // Stale approvals terminate: only the current revision is
      // approvable, so an older accepted revision can never be
      // re-armed after a correction supersedes it (AC-12).
      throw new ExtractionConflictException("revision is superseded");
    }
    tenant.update(
        "UPDATE extraction_record SET approved_revision = ? WHERE id = ?", revision, recordId);
    audit.record(
        caller,
        Action.EXTRACTION_APPROVE,
        ResourceRef.tenantScoped("extraction-record", recordId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of("revision", String.valueOf(revision)));
    return new ApprovalResult(recordId, revision);
  }

  @Transactional(noRollbackFor = ForbiddenException.class)
  public RecordView read(ServiceAccountPrincipal caller, UUID recordId) {
    Decision decision =
        require(caller, Action.EXTRACTION_READ, "extraction-record", recordId.toString());
    RecordRow record = recordRow(recordId);
    List<RevisionView> revisions =
        tenant.query(
            "SELECT rev_no, observed, normalized, confidence, canonical_digests, exact_digests,"
                + " supersedes, created_by FROM extraction_revision"
                + " WHERE record_id = ? ORDER BY rev_no",
            (rs, row) -> new RevisionView(
                rs.getInt("rev_no"),
                readJson(rs.getString("observed")),
                readJson(rs.getString("normalized")),
                readJson(rs.getString("canonical_digests")),
                readJson(rs.getString("exact_digests")),
                rs.getBigDecimal("confidence"),
                rs.getObject("supersedes", Integer.class),
                rs.getString("created_by")),
            recordId);
    audit.record(
        caller,
        Action.EXTRACTION_READ,
        ResourceRef.tenantScoped("extraction-record", recordId.toString(), caller.tenantId()),
        decision,
        "",
        Map.of(
            "revisions", String.valueOf(revisions.size()),
            "approved", String.valueOf(record.approved)));
    return new RecordView(
        recordId,
        record.vaultObjectId,
        record.objectVersion,
        HexFormat.of().formatHex(record.sourceDigest),
        record.engineId,
        record.schemaId,
        record.normalizerId,
        record.canonId,
        record.approved,
        revisions);
  }

  private void insertRevision(
      ServiceAccountPrincipal caller,
      UUID recordId,
      int revNo,
      Integer supersedes,
      Map<String, String> observed,
      double confidence) {
    Map<String, String> ordered = new TreeMap<>(observed);
    Map<String, String> normalized = new TreeMap<>();
    Map<String, String> canonical = new TreeMap<>();
    Map<String, String> exact = new TreeMap<>();
    for (Map.Entry<String, String> field : ordered.entrySet()) {
      String norm = FieldNormalizer.normalize(field.getKey(), field.getValue());
      normalized.put(field.getKey(), norm);
      canonical.put(field.getKey(), HexFormat.of().formatHex(FieldDigests.canonical(norm)));
      exact.put(field.getKey(), HexFormat.of().formatHex(FieldDigests.exact(field.getValue())));
    }
    tenant.update(
        "INSERT INTO extraction_revision (tenant_id, record_id, rev_no, observed, normalized,"
            + " confidence, canonical_digests, exact_digests, supersedes, created_by)"
            + " VALUES (?, ?, ?, ?::jsonb, ?::jsonb, ?, ?::jsonb, ?::jsonb, ?, ?)",
        caller.tenantId(),
        recordId,
        revNo,
        writeJson(ordered),
        writeJson(normalized),
        BigDecimal.valueOf(confidence),
        writeJson(canonical),
        writeJson(exact),
        supersedes,
        caller.name());
  }

  private String writeJson(Map<String, String> fields) {
    try {
      return mapper.writeValueAsString(fields);
    } catch (Exception e) {
      throw new IllegalStateException("field map is not serializable", e);
    }
  }

  private Map<String, String> readJson(String json) {
    try {
      Map<String, String> fields = new TreeMap<>();
      Map<?, ?> parsed = mapper.readValue(json, Map.class);
      for (Map.Entry<?, ?> entry : parsed.entrySet()) {
        fields.put(String.valueOf(entry.getKey()), String.valueOf(entry.getValue()));
      }
      return fields;
    } catch (Exception e) {
      throw new IllegalStateException("stored field map is not readable", e);
    }
  }

  private record RecordRow(
      UUID vaultObjectId,
      int objectVersion,
      byte[] sourceDigest,
      String engineId,
      String schemaId,
      String normalizerId,
      String canonId,
      Integer approved,
      int maxRev) {}

  private RecordRow recordRow(UUID recordId) {
    List<RecordRow> rows =
        tenant.query(
            "SELECT r.vault_object_id, r.object_version, r.source_digest, r.engine_id,"
                + " r.schema_id, r.normalizer_id, r.canon_id, r.approved_revision,"
                + " COALESCE(MAX(v.rev_no), 0) AS max_rev"
                + " FROM extraction_record r"
                + " LEFT JOIN extraction_revision v ON v.record_id = r.id"
                + " WHERE r.id = ?"
                + " GROUP BY r.vault_object_id, r.object_version, r.source_digest, r.engine_id,"
                + " r.schema_id, r.normalizer_id, r.canon_id, r.approved_revision",
            (rs, row) -> new RecordRow(
                rs.getObject("vault_object_id", UUID.class),
                rs.getInt("object_version"),
                rs.getBytes("source_digest"),
                rs.getString("engine_id"),
                rs.getString("schema_id"),
                rs.getString("normalizer_id"),
                rs.getString("canon_id"),
                rs.getObject("approved_revision", Integer.class),
                rs.getInt("max_rev")),
            recordId);
    if (rows.isEmpty()) {
      throw new ExtractionNotFoundException();
    }
    return rows.get(0);
  }

  private Decision require(
      ServiceAccountPrincipal caller, Action action, String type, String id) {
    return AuditedAuthorizer.require(
        authz, audit, caller, action, ResourceRef.tenantScoped(type, id, caller.tenantId()));
  }
}
