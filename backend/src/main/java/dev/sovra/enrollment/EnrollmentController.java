package dev.sovra.enrollment;

import dev.sovra.auth.CurrentPrincipal;
import dev.sovra.enrollment.EnrollmentService.Created;
import dev.sovra.enrollment.EnrollmentService.DecisionView;
import dev.sovra.enrollment.EnrollmentService.EligibilityView;
import dev.sovra.enrollment.EnrollmentService.EnrollmentView;
import dev.sovra.enrollment.EnrollmentService.ReviewView;
import dev.sovra.enrollment.EnrollmentService.StateView;
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
import tools.jackson.databind.JsonNode;

/**
 * Enrollment review desk (SOV-019, OD-14). Cases bind approved
 * extraction revisions to opaque subjects and holder keys;
 * maker/checker separation and revision-specific decisions keep
 * unreviewed or stale sources out of issuance eligibility.
 */
@RestController
@RequestMapping("/api/enrollments")
public class EnrollmentController {

  private final EnrollmentService enrollment;

  public EnrollmentController(EnrollmentService enrollment) {
    this.enrollment = enrollment;
  }

  public record CreateRequest(
      @NotNull UUID vaultObjectId,
      @NotNull UUID extractionRecordId,
      @NotNull JsonNode holderJwk) {}

  public record DecideRequest(@Min(1) int revision, @NotBlank String decision, String bindingProof) {}

  @PostMapping
  public ResponseEntity<Map<String, Object>> create(@Valid @RequestBody CreateRequest request) {
    var caller = CurrentPrincipal.require();
    Created created = enrollment.create(
        caller, request.vaultObjectId(), request.extractionRecordId(), request.holderJwk());
    return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
        "enrollmentId", created.enrollmentId().toString(),
        "subjectRef", created.subjectRef().toString(),
        "state", created.state().name()));
  }

  @PostMapping("/{id}/submit")
  public ResponseEntity<Map<String, Object>> submit(@PathVariable("id") UUID id) {
    var caller = CurrentPrincipal.require();
    StateView state = enrollment.submit(caller, id);
    return ResponseEntity.ok(Map.of(
        "enrollmentId", state.enrollmentId().toString(), "state", state.state().name()));
  }

  @PostMapping("/{id}/decision")
  public ResponseEntity<Map<String, Object>> decide(
      @PathVariable("id") UUID id, @Valid @RequestBody DecideRequest request) {
    var caller = CurrentPrincipal.require();
    DecisionView decided = enrollment.decide(
        caller, id, request.revision(), request.decision(), request.bindingProof());
    return ResponseEntity.ok(Map.of(
        "enrollmentId", decided.enrollmentId().toString(),
        "state", decided.state().name(),
        "boundRevision", decided.boundRevision()));
  }

  @GetMapping
  public ResponseEntity<Map<String, Object>> list(
      @RequestParam(required = false) String state,
      @RequestParam(defaultValue = "50") int limit,
      @RequestParam(required = false) String cursor) {
    var caller = CurrentPrincipal.require();
    EnrollmentService.EnrollmentPage page =
        enrollment.listEnrollments(caller, state, limit, cursor);
    List<Map<String, Object>> items = new ArrayList<>();
    for (EnrollmentService.EnrollmentSummary summary : page.items()) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("enrollmentId", summary.enrollmentId().toString());
      entry.put("subjectRef", summary.subjectRef().toString());
      entry.put("vaultObjectId", summary.vaultObjectId().toString());
      entry.put("extractionRecordId", summary.extractionRecordId().toString());
      entry.put("boundRevision", summary.boundRevision());
      entry.put("state", summary.state().name());
      entry.put("createdBy", summary.createdBy());
      entry.put("decidedBy", summary.decidedBy());
      entry.put("eligible", summary.eligible());
      entry.put("eligibilityReason", summary.eligibilityReason());
      entry.put("createdAt", summary.createdAt());
      items.add(entry);
    }
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("items", items);
    body.put("nextCursor", page.nextCursor());
    return ResponseEntity.ok(body);
  }

  @GetMapping("/{id}")
  public ResponseEntity<Map<String, Object>> get(
      @PathVariable("id") UUID id,
      @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch) {
    var caller = CurrentPrincipal.require();
    EnrollmentView view = enrollment.read(caller, id);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("enrollmentId", view.enrollmentId().toString());
    body.put("subjectRef", view.subjectRef().toString());
    body.put("vaultObjectId", view.vaultObjectId().toString());
    body.put("extractionRecordId", view.extractionRecordId().toString());
    body.put("boundRevision", view.boundRevision());
    body.put("state", view.state().name());
    body.put("createdBy", view.createdBy());
    body.put("decidedBy", view.decidedBy());
    body.put("eligible", view.eligible());
    body.put("eligibilityReason", view.eligibilityReason());
    List<Map<String, Object>> reviews = new ArrayList<>();
    for (ReviewView review : view.reviews()) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("revision", review.revision());
      entry.put("decision", review.decision());
      entry.put("bindingProofOk", review.bindingProofOk());
      entry.put("reviewer", review.reviewer());
      reviews.add(entry);
    }
    body.put("reviews", reviews);
    return Etags.respond(body, ifNoneMatch);
  }

  @GetMapping("/{id}/eligibility")
  public ResponseEntity<Map<String, Object>> eligibility(@PathVariable("id") UUID id) {
    var caller = CurrentPrincipal.require();
    EligibilityView view = enrollment.eligibilityFor(caller, id);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("enrollmentId", view.enrollmentId().toString());
    body.put("eligible", view.eligible());
    body.put("reason", view.reason());
    body.put("claims", view.claims());
    return ResponseEntity.ok(body);
  }
}
