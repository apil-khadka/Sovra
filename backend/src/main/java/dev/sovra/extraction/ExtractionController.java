package dev.sovra.extraction;

import dev.sovra.auth.CurrentPrincipal;
import dev.sovra.extraction.ExtractionService.ApprovalResult;
import dev.sovra.extraction.ExtractionService.CorrectionResult;
import dev.sovra.extraction.ExtractionService.RecordView;
import dev.sovra.extraction.ExtractionService.RevisionView;
import dev.sovra.extraction.ExtractionService.RunResult;
import dev.sovra.web.Etags;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Local extraction runs (SOV-018). Runs read one vault source
 * version through a purpose grant, corrections append revisions,
 * and approvals pin the current revision — digests stay protected
 * references inside authorized reads.
 */
@RestController
@RequestMapping("/api/extraction")
public class ExtractionController {

  private final ExtractionService extraction;

  public ExtractionController(ExtractionService extraction) {
    this.extraction = extraction;
  }

  public record RunRequest(
      @NotNull UUID vaultObjectId,
      @Min(1) int objectVersion,
      @NotNull UUID grantId,
      @NotBlank String purpose,
      @NotBlank String workload,
      @NotBlank String schemaId) {}

  public record CorrectRequest(Map<String, String> fields, double confidence) {}

  public record ApproveRequest(@Min(1) int revision) {}

  @PostMapping("/records")
  public ResponseEntity<Map<String, Object>> run(@Valid @RequestBody RunRequest request) {
    var caller = CurrentPrincipal.require();
    RunResult result =
        extraction.extract(
            caller,
            request.vaultObjectId(),
            request.objectVersion(),
            request.grantId(),
            request.purpose(),
            request.workload(),
            request.schemaId());
    return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
        "recordId", result.recordId().toString(),
        "revision", result.revision(),
        "sourceDigestHex", result.sourceDigestHex()));
  }

  @PostMapping("/records/{id}/revisions")
  public ResponseEntity<Map<String, Object>> correct(
      @PathVariable("id") UUID id, @Valid @RequestBody CorrectRequest request) {
    var caller = CurrentPrincipal.require();
    CorrectionResult result =
        extraction.correct(caller, id, request.fields(), request.confidence());
    return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
        "recordId", result.recordId().toString(), "revision", result.revision()));
  }

  @PostMapping("/records/{id}/approval")
  public ResponseEntity<Map<String, Object>> approve(
      @PathVariable("id") UUID id, @Valid @RequestBody ApproveRequest request) {
    var caller = CurrentPrincipal.require();
    ApprovalResult result = extraction.approve(caller, id, request.revision());
    return ResponseEntity.ok(Map.of(
        "recordId", result.recordId().toString(),
        "approvedRevision", result.approvedRevision()));
  }

  @GetMapping("/records")
  public ResponseEntity<Map<String, Object>> list(
      @RequestParam(required = false) String state,
      @RequestParam(defaultValue = "50") int limit,
      @RequestParam(required = false) String cursor) {
    var caller = CurrentPrincipal.require();
    ExtractionService.RecordPage page = extraction.listRecords(caller, state, limit, cursor);
    List<Map<String, Object>> items = new ArrayList<>();
    for (ExtractionService.RecordSummary summary : page.items()) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("recordId", summary.recordId().toString());
      entry.put("vaultObjectId", summary.vaultObjectId().toString());
      entry.put("objectVersion", summary.objectVersion());
      entry.put("engineId", summary.engineId());
      entry.put("schemaId", summary.schemaId());
      entry.put("approvedRevision", summary.approvedRevision());
      entry.put("latestRevision", summary.latestRevision());
      entry.put("createdBy", summary.createdBy());
      entry.put("createdAt", summary.createdAt());
      items.add(entry);
    }
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("items", items);
    body.put("nextCursor", page.nextCursor());
    return ResponseEntity.ok(body);
  }

  @GetMapping("/records/{id}")
  public ResponseEntity<Map<String, Object>> get(
      @PathVariable("id") UUID id,
      @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch) {
    var caller = CurrentPrincipal.require();
    RecordView view = extraction.read(caller, id);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("recordId", view.recordId().toString());
    body.put("vaultObjectId", view.vaultObjectId().toString());
    body.put("objectVersion", view.objectVersion());
    body.put("sourceDigestHex", view.sourceDigestHex());
    body.put("engineId", view.engineId());
    body.put("schemaId", view.schemaId());
    body.put("normalizerId", view.normalizerId());
    body.put("canonId", view.canonId());
    body.put("approvedRevision", view.approvedRevision());
    List<Map<String, Object>> revisions = new ArrayList<>();
    for (RevisionView revision : view.revisions()) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("revNo", revision.revNo());
      entry.put("observed", revision.observed());
      entry.put("normalized", revision.normalized());
      entry.put("canonicalDigests", revision.canonicalDigestHex());
      entry.put("exactDigests", revision.exactDigestHex());
      entry.put("confidence", revision.confidence());
      entry.put("supersedes", revision.supersedes());
      entry.put("createdBy", revision.createdBy());
      revisions.add(entry);
    }
    body.put("revisions", revisions);
    return Etags.respond(body, ifNoneMatch);
  }
}
