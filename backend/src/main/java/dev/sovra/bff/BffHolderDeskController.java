package dev.sovra.bff;

import dev.sovra.auth.CurrentPrincipal;
import dev.sovra.bff.HolderDeskService.CaseDetail;
import dev.sovra.bff.HolderDeskService.Disclosure;
import dev.sovra.bff.HolderDeskService.HolderCase;
import dev.sovra.bff.HolderDeskService.HolderCredential;
import dev.sovra.bff.HolderDeskService.RecoveryStatus;
import dev.sovra.bff.HolderUnlockService.Challenge;
import dev.sovra.bff.HolderUnlockService.Unlock;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;

/**
 * Holder dashboard (SOV-024): enrollment cases with their
 * corrections, disclosure history with verification outcomes,
 * credentials, and recovery — for exactly the holder key the
 * session unlocked. No request carries a thumbprint or subject;
 * the server-side unlock selects the key, so holders can
 * neither list nor guess each other's history.
 */
@RestController
@RequestMapping("/api/bff/holder")
@ConditionalOnProperty(name = "sovra.bff.enabled", havingValue = "true")
public class BffHolderDeskController {

  private final HolderUnlockService unlock;
  private final HolderDeskService desk;

  public BffHolderDeskController(HolderUnlockService unlock, HolderDeskService desk) {
    this.unlock = unlock;
    this.desk = desk;
  }

  public record UnlockRequest(JsonNode holderJwk, String proof) {}

  @GetMapping("/challenge")
  public ResponseEntity<Map<String, String>> challenge(HttpServletRequest request) {
    CurrentPrincipal.require();
    Challenge issued = unlock.challenge(request.getSession(true));
    return ResponseEntity.ok(
        Map.of("challenge", issued.value(), "expiresAt", issued.expiresAt().toString()));
  }

  @PostMapping("/unlock")
  public ResponseEntity<Map<String, String>> unlock(
      HttpServletRequest request, @Valid @RequestBody UnlockRequest body) {
    CurrentPrincipal.require();
    Unlock bound = unlock.unlock(request.getSession(true), body.holderJwk(), body.proof());
    return ResponseEntity.ok(
        Map.of("thumbprint", bound.thumbprint(), "expiresAt", bound.expiresAt().toString()));
  }

  @PostMapping("/lock")
  public ResponseEntity<Map<String, String>> lock(HttpServletRequest request) {
    CurrentPrincipal.require();
    unlock.lock(request.getSession(true));
    return ResponseEntity.ok(Map.of("locked", "true"));
  }

  @GetMapping("/cases")
  public ResponseEntity<List<Map<String, Object>>> cases(HttpServletRequest request) {
    var caller = CurrentPrincipal.require();
    String thumbprint = unlock.requireUnlock(request.getSession(false));
    List<Map<String, Object>> items = new ArrayList<>();
    for (HolderCase item : desk.cases(caller, thumbprint)) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("enrollmentId", item.enrollmentId().toString());
      entry.put("subjectRef", item.subjectRef().toString());
      entry.put("vaultObjectId", item.vaultObjectId().toString());
      entry.put("extractionRecordId", item.extractionRecordId().toString());
      entry.put("boundRevision", item.boundRevision());
      entry.put("state", item.state().name());
      entry.put("createdBy", item.createdBy());
      entry.put("decidedBy", item.decidedBy());
      entry.put("eligible", item.eligible());
      entry.put("eligibilityReason", item.eligibilityReason());
      entry.put("createdAt", item.createdAt());
      items.add(entry);
    }
    return ResponseEntity.ok(items);
  }

  @GetMapping("/cases/{id}")
  public ResponseEntity<Map<String, Object>> oneCase(
      HttpServletRequest request, @PathVariable("id") UUID id) {
    var caller = CurrentPrincipal.require();
    String thumbprint = unlock.requireUnlock(request.getSession(false));
    CaseDetail view = desk.caseDetail(caller, thumbprint, id);
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
    for (HolderDeskService.CaseReview review : view.reviews()) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("revision", review.revision());
      entry.put("decision", review.decision());
      entry.put("bindingProofOk", review.bindingProofOk());
      entry.put("reviewer", review.reviewer());
      reviews.add(entry);
    }
    body.put("reviews", reviews);
    body.put("approvedRevision", view.approvedRevision());
    List<Map<String, Object>> revisions = new ArrayList<>();
    for (HolderDeskService.CaseRevision revision : view.revisions()) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("revNo", revision.revNo());
      entry.put("observed", revision.observed());
      entry.put("normalized", revision.normalized());
      entry.put("confidence", revision.confidence());
      entry.put("supersedes", revision.supersedes());
      entry.put("createdBy", revision.createdBy());
      revisions.add(entry);
    }
    body.put("revisions", revisions);
    return ResponseEntity.ok(body);
  }

  @GetMapping("/consents")
  public ResponseEntity<List<Map<String, Object>>> consents(HttpServletRequest request) {
    var caller = CurrentPrincipal.require();
    String thumbprint = unlock.requireUnlock(request.getSession(false));
    List<Map<String, Object>> items = new ArrayList<>();
    for (Disclosure item : desk.disclosures(caller, thumbprint)) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("requestId", item.requestId().toString());
      entry.put("rpId", item.rpId());
      entry.put("audience", item.audience());
      entry.put("purpose", item.purpose());
      entry.put("credentialId", item.credentialId().toString());
      entry.put("claims", item.claims());
      entry.put("state", item.state());
      entry.put("createdAt", item.createdAt());
      entry.put("expiresAt", item.expiresAt());
      entry.put("decidedAt", item.decidedAt());
      entry.put("verificationOutcome", item.verificationOutcome());
      entry.put("trustSnapshot", item.trustSnapshot());
      items.add(entry);
    }
    return ResponseEntity.ok(items);
  }

  @GetMapping("/credentials")
  public ResponseEntity<List<Map<String, Object>>> credentials(HttpServletRequest request) {
    var caller = CurrentPrincipal.require();
    String thumbprint = unlock.requireUnlock(request.getSession(false));
    List<Map<String, Object>> items = new ArrayList<>();
    for (HolderCredential item : desk.credentials(caller, thumbprint)) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("credentialId", item.credentialId().toString());
      entry.put("issuerId", item.issuerId());
      entry.put("vct", item.vct());
      entry.put("keyRef", item.keyRef());
      entry.put("issuedAt", item.issuedAt());
      entry.put("expiresAt", item.expiresAt());
      entry.put("status", item.status());
      entry.put("trustSnapshot", item.trustSnapshot());
      items.add(entry);
    }
    return ResponseEntity.ok(items);
  }

  @GetMapping("/recovery")
  public ResponseEntity<Map<String, Object>> recovery(HttpServletRequest request) {
    var caller = CurrentPrincipal.require();
    String thumbprint = unlock.requireUnlock(request.getSession(false));
    RecoveryStatus view = desk.recovery(caller, thumbprint);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("keyId", view.keyId() == null ? null : view.keyId().toString());
    body.put("thumbprint", view.thumbprint());
    body.put("status", view.status());
    List<Map<String, Object>> attempts = new ArrayList<>();
    for (HolderDeskService.RecoveryAttempt attempt : view.recoveries()) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("recoveryId", attempt.recoveryId().toString());
      entry.put("reason", attempt.reason());
      entry.put("state", attempt.state());
      entry.put("newThumbprint", attempt.newThumbprint());
      entry.put("createdAt", attempt.createdAt());
      attempts.add(entry);
    }
    body.put("recoveries", attempts);
    return ResponseEntity.ok(body);
  }
}
