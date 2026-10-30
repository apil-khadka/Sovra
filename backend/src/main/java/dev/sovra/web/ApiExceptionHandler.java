package dev.sovra.web;

import dev.sovra.audit.AuditCursorException;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.TenantMismatchException;
import dev.sovra.consent.ConsentNotFoundException;
import dev.sovra.consent.InvalidConsentException;
import dev.sovra.guard.GuardRejectedException;
import dev.sovra.guard.MalformedPlanException;
import dev.sovra.issuance.CredentialNotFoundException;
import dev.sovra.issuance.IdempotencyConflictException;
import dev.sovra.issuance.InvalidIssuanceException;
import dev.sovra.issuance.SigningRefusedException;
import dev.sovra.issuance.TrustUnavailableException;
import dev.sovra.planning.InvalidPlanningException;
import dev.sovra.planning.PlanningUnavailableException;
import dev.sovra.tenancy.TenantRequiredException;
import dev.sovra.trust.AlreadyDecidedException;
import dev.sovra.trust.IssuerKeyConflictException;
import dev.sovra.trust.IssuerKeyNotFoundException;
import dev.sovra.verification.InvalidVerificationException;
import dev.sovra.verification.VerificationConflictException;
import dev.sovra.verification.VerificationNotFoundException;
import dev.sovra.trust.InvalidProposalException;
import dev.sovra.trust.ProposalNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

/**
 * Leak-free error mapping. 404s carry empty bodies so responses never
 * confirm or deny another tenant's objects; 403s carry only a reason code.
 *
 * <p>SOV-015 compatibility: the default bodies are the frozen legacy
 * contract (byte-identical). Clients that send
 * {@code Accept: application/problem+json} receive RFC 9457 problem
 * details (type/title/status plus Sovra {@code code}/{@code correlationId}/
 * {@code retryable} extensions) instead; 404s stay empty in both variants.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

  private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

  static final MediaType PROBLEM_JSON = MediaType.parseMediaType("application/problem+json");

  static boolean wantsProblem(HttpServletRequest request) {
    if (request == null) {
      return false;
    }
    String accept = request.getHeader("Accept");
    return accept != null && accept.contains(PROBLEM_JSON.toString());
  }

  private ResponseEntity<Object> problem(HttpStatus status, String code, boolean retryable) {
    // Explicit member order: type/title/status are the RFC 9457
    // registered fields, the rest are Sovra extensions. Built by hand
    // so the shape never depends on Jackson mixin registration.
    Map<String, Object> detail = new java.util.LinkedHashMap<>();
    detail.put("type", "about:blank");
    detail.put("title", code);
    detail.put("status", status.value());
    detail.put("code", code);
    detail.put("correlationId", UUID.randomUUID().toString());
    detail.put("retryable", retryable);
    return ResponseEntity.status(status).contentType(PROBLEM_JSON).body(detail);
  }

  @ExceptionHandler({
    TenantMismatchException.class,
    ProposalNotFoundException.class,
    CredentialNotFoundException.class,
    ConsentNotFoundException.class,
    VerificationNotFoundException.class,
    IssuerKeyNotFoundException.class,
    dev.sovra.auth.ServiceAccountService.ServiceAccountNotFoundException.class,
    dev.sovra.vault.VaultNotFoundException.class,
    dev.sovra.quarantine.QuarantineNotFoundException.class,
    dev.sovra.extraction.ExtractionNotFoundException.class,
    dev.sovra.enrollment.EnrollmentNotFoundException.class,
    dev.sovra.custody.HolderCustodyNotFoundException.class,
    dev.sovra.openid.OpenIdNotFoundException.class
  })
  public ResponseEntity<Void> notFound() {
    return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
  }

  @ExceptionHandler(dev.sovra.openid.OpenIdProtocolException.class)
  public ResponseEntity<Object> openIdProtocol(
      dev.sovra.openid.OpenIdProtocolException e, HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.BAD_REQUEST, e.error(), false);
    }
    // OAuth2 error shape: registered code only, no oracle detail.
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.error()));
  }

  @ExceptionHandler(ForbiddenException.class)
  public ResponseEntity<Object> forbidden(ForbiddenException e, HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.FORBIDDEN, "forbidden:" + e.reasonCode().name(), false);
    }
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
        .body(Map.of("error", "forbidden", "reason", e.reasonCode().name()));
  }

  @ExceptionHandler({
    InvalidProposalException.class,
    InvalidIssuanceException.class,
    InvalidConsentException.class,
    InvalidVerificationException.class,
    InvalidPlanningException.class,
    dev.sovra.openid.InvalidOpenIdRequestException.class,
    dev.sovra.auth.ServiceAccountService.InvalidServiceAccountException.class,
    AuditCursorException.class,
    GuardRejectedException.class,
    MalformedPlanException.class,
    MethodArgumentNotValidException.class,
    MissingRequestHeaderException.class,
    HttpMessageNotReadableException.class,
    MethodArgumentTypeMismatchException.class
  })
  public ResponseEntity<Object> invalid(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.BAD_REQUEST, "invalid_request", false);
    }
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_request"));
  }

  @ExceptionHandler(IdempotencyConflictException.class)
  public ResponseEntity<Object> idempotencyConflict(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.CONFLICT, "idempotency_conflict", false);
    }
    return ResponseEntity.status(HttpStatus.CONFLICT)
        .body(Map.of("error", "idempotency_conflict"));
  }

  @ExceptionHandler(
      dev.sovra.auth.ServiceAccountService.ServiceAccountConflictException.class)
  public ResponseEntity<Object> serviceAccountConflict(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.CONFLICT, "service_account_conflict", false);
    }
    return ResponseEntity.status(HttpStatus.CONFLICT)
        .body(Map.of("error", "service_account_conflict"));
  }

  @ExceptionHandler(VerificationConflictException.class)
  public ResponseEntity<Object> verificationConflict(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.CONFLICT, "verification_conflict", false);
    }
    return ResponseEntity.status(HttpStatus.CONFLICT)
        .body(Map.of("error", "verification_conflict"));
  }

  @ExceptionHandler(TrustUnavailableException.class)
  public ResponseEntity<Object> trustUnavailable(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.SERVICE_UNAVAILABLE, "dependency_unavailable", true);
    }
    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
        .body(Map.of("error", "trust_unavailable"));
  }

  @ExceptionHandler(PlanningUnavailableException.class)
  public ResponseEntity<Object> planningUnavailable(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.SERVICE_UNAVAILABLE, "dependency_unavailable", true);
    }
    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
        .body(Map.of("error", "planning_unavailable"));
  }

  @ExceptionHandler(dev.sovra.issuance.KmsUnavailableException.class)
  public ResponseEntity<Object> kmsUnavailable(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.SERVICE_UNAVAILABLE, "dependency_unavailable", true);
    }
    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
        .body(Map.of("error", "kms_unavailable"));
  }

  @ExceptionHandler(AlreadyDecidedException.class)
  public ResponseEntity<Object> conflict(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.CONFLICT, "already_decided", false);
    }
    return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "already_decided"));
  }

  @ExceptionHandler(IssuerKeyConflictException.class)
  public ResponseEntity<Object> issuerKeyConflict(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.CONFLICT, "issuer_key_conflict", false);
    }
    return ResponseEntity.status(HttpStatus.CONFLICT)
        .body(Map.of("error", "issuer_key_conflict"));
  }

  @ExceptionHandler(TenantRequiredException.class)
  public ResponseEntity<Object> serverError(TenantRequiredException e, HttpServletRequest request) {
    log.error("tenant context missing on an authenticated path", e);
    if (wantsProblem(request)) {
      return problem(HttpStatus.INTERNAL_SERVER_ERROR, "internal", false);
    }
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(Map.of("error", "internal"));
  }

  @ExceptionHandler(SigningRefusedException.class)
  public ResponseEntity<Object> signingRefused(SigningRefusedException e, HttpServletRequest request) {
    log.error("signer refused a signing call", e);
    if (wantsProblem(request)) {
      return problem(HttpStatus.INTERNAL_SERVER_ERROR, "internal", false);
    }
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(Map.of("error", "internal"));
  }

  @ExceptionHandler(dev.sovra.vault.VaultInvalidException.class)
  public ResponseEntity<Object> vaultInvalid(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.BAD_REQUEST, "invalid_request", false);
    }
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_request"));
  }

  @ExceptionHandler(dev.sovra.quarantine.QuarantineInvalidException.class)
  public ResponseEntity<Object> quarantineInvalid(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.BAD_REQUEST, "invalid_request", false);
    }
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_request"));
  }

  @ExceptionHandler(dev.sovra.quarantine.QuarantineConflictException.class)
  public ResponseEntity<Object> quarantineConflict(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.CONFLICT, "quarantine_conflict", false);
    }
    return ResponseEntity.status(HttpStatus.CONFLICT)
        .body(Map.of("error", "quarantine_conflict"));
  }

  @ExceptionHandler(dev.sovra.extraction.ExtractionInvalidException.class)
  public ResponseEntity<Object> extractionInvalid(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.BAD_REQUEST, "invalid_request", false);
    }
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_request"));
  }

  @ExceptionHandler(dev.sovra.extraction.ExtractionConflictException.class)
  public ResponseEntity<Object> extractionConflict(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.CONFLICT, "extraction_conflict", false);
    }
    return ResponseEntity.status(HttpStatus.CONFLICT)
        .body(Map.of("error", "extraction_conflict"));
  }

  @ExceptionHandler(dev.sovra.enrollment.EnrollmentInvalidException.class)
  public ResponseEntity<Object> enrollmentInvalid(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.BAD_REQUEST, "invalid_request", false);
    }
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_request"));
  }

  @ExceptionHandler(dev.sovra.enrollment.EnrollmentConflictException.class)
  public ResponseEntity<Object> enrollmentConflict(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.CONFLICT, "enrollment_conflict", false);
    }
    return ResponseEntity.status(HttpStatus.CONFLICT)
        .body(Map.of("error", "enrollment_conflict"));
  }

  @ExceptionHandler(dev.sovra.custody.HolderCustodyInvalidException.class)
  public ResponseEntity<Object> holderCustodyInvalid(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.BAD_REQUEST, "invalid_request", false);
    }
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_request"));
  }

  @ExceptionHandler(dev.sovra.custody.HolderCustodyConflictException.class)
  public ResponseEntity<Object> holderCustodyConflict(HttpServletRequest request) {
    if (wantsProblem(request)) {
      return problem(HttpStatus.CONFLICT, "holder_custody_conflict", false);
    }
    return ResponseEntity.status(HttpStatus.CONFLICT)
        .body(Map.of("error", "holder_custody_conflict"));
  }

  @ExceptionHandler(dev.sovra.vault.VaultAuthenticationException.class)
  public ResponseEntity<Object> vaultIntegrityFailure(HttpServletRequest request) {
    log.error("vault integrity failure: ciphertext, context, or key mismatch");
    if (wantsProblem(request)) {
      return problem(HttpStatus.INTERNAL_SERVER_ERROR, "vault_integrity_failure", false);
    }
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(Map.of("error", "vault_integrity_failure"));
  }
}
