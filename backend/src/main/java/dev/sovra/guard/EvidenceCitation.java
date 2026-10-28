package dev.sovra.guard;

/** Reference to one versioned source section grounding a claimed mapping. */
public record EvidenceCitation(String documentId, String sectionId) {}
