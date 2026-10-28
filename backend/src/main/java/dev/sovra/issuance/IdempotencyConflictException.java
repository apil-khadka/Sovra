package dev.sovra.issuance;

/** Same idempotency key, different request. Maps to 422. */
public class IdempotencyConflictException extends RuntimeException {}
