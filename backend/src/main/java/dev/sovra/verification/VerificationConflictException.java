package dev.sovra.verification;

/**
 * The same nonce already decided different content. The stored decision
 * stands; the conflicting submission decides nothing. Maps to 422.
 */
public class VerificationConflictException extends RuntimeException {}
