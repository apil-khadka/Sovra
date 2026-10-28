package dev.sovra.guard;

import java.util.List;
import java.util.Map;

/** One versioned policy document with addressable sections and a claim budget. */
public record PolicyDocument(
    String documentId,
    String version,
    Map<String, String> sections,
    List<String> approvedClaims) {}
