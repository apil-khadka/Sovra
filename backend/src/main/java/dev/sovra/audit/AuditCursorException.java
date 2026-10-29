package dev.sovra.audit;

/** Malformed audit-list cursor. Maps to 400 without disclosing stored rows. */
public class AuditCursorException extends RuntimeException {

  public AuditCursorException(String message) {
    super(message);
  }
}
