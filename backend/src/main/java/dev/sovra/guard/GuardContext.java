package dev.sovra.guard;

import java.util.Map;

/** Trust and policy inputs the guard validates a plan against. */
public record GuardContext(
    Map<String, TrustedIssuer> trustedIssuers, Map<String, PolicyDocument> policies) {}
