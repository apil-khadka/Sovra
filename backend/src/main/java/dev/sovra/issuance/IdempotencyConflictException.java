package dev.sovra.issuance;

/** Same idempotency key, different request. Maps to 409. */
public class IdempotencyConflictException extends RuntimeException {}
