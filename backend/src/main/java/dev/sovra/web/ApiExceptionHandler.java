package dev.sovra.web;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.TenantMismatchException;
import dev.sovra.consent.ConsentNotFoundException;
import dev.sovra.consent.InvalidConsentException;
import dev.sovra.issuance.CredentialNotFoundException;
import dev.sovra.issuance.IdempotencyConflictException;
import dev.sovra.issuance.InvalidIssuanceException;
import dev.sovra.issuance.SigningRefusedException;
import dev.sovra.issuance.TrustUnavailableException;
import dev.sovra.tenancy.TenantRequiredException;
import dev.sovra.trust.AlreadyDecidedException;
import dev.sovra.verification.InvalidVerificationException;
import dev.sovra.verification.VerificationConflictException;
import dev.sovra.verification.VerificationNotFoundException;
import dev.sovra.trust.InvalidProposalException;
import dev.sovra.trust.ProposalNotFoundException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
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
 */
@RestControllerAdvice
public class ApiExceptionHandler {

  private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

  @ExceptionHandler({
    TenantMismatchException.class,
    ProposalNotFoundException.class,
    CredentialNotFoundException.class,
    ConsentNotFoundException.class,
    VerificationNotFoundException.class
  })
  public ResponseEntity<Void> notFound() {
    return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
  }

  @ExceptionHandler(ForbiddenException.class)
  public ResponseEntity<Map<String, String>> forbidden(ForbiddenException e) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
        .body(Map.of("error", "forbidden", "reason", e.reasonCode().name()));
  }

  @ExceptionHandler({
    InvalidProposalException.class,
    InvalidIssuanceException.class,
    InvalidConsentException.class,
    InvalidVerificationException.class,
    MethodArgumentNotValidException.class,
    MissingRequestHeaderException.class,
    HttpMessageNotReadableException.class,
    MethodArgumentTypeMismatchException.class
  })
  public ResponseEntity<Map<String, String>> invalid() {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_request"));
  }

  @ExceptionHandler(IdempotencyConflictException.class)
  public ResponseEntity<Map<String, String>> idempotencyConflict() {
    return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
        .body(Map.of("error", "idempotency_conflict"));
  }

  @ExceptionHandler(VerificationConflictException.class)
  public ResponseEntity<Map<String, String>> verificationConflict() {
    return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
        .body(Map.of("error", "verification_conflict"));
  }

  @ExceptionHandler(TrustUnavailableException.class)
  public ResponseEntity<Map<String, String>> trustUnavailable() {
    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
        .body(Map.of("error", "trust_unavailable"));
  }

  @ExceptionHandler(AlreadyDecidedException.class)
  public ResponseEntity<Map<String, String>> conflict() {
    return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "already_decided"));
  }

  @ExceptionHandler(TenantRequiredException.class)
  public ResponseEntity<Map<String, String>> serverError(TenantRequiredException e) {
    log.error("tenant context missing on an authenticated path", e);
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(Map.of("error", "internal"));
  }

  @ExceptionHandler(SigningRefusedException.class)
  public ResponseEntity<Map<String, String>> signingRefused(SigningRefusedException e) {
    log.error("signer refused a signing call", e);
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(Map.of("error", "internal"));
  }
}
