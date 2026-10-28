package dev.sovra.guard;

import java.time.Instant;

/**
 * Explicit guard inputs (NFR-06): the rules version under test plus the
 * clock instant standing checks run against. Domain decisions take no
 * ambient time, configuration, or framework state.
 */
public record GuardInputs(String rulesVersion, Instant now) {}
