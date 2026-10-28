package dev.sovra.guard;

import java.util.List;

/** Candidate evidence mapping proposed by the AI planner: untrusted until the guard accepts it. */
public record CandidatePlan(
    String planId,
    String requestedOutcome,
    String candidateIssuerId,
    String credentialType,
    List<String> claimPaths,
    List<EvidenceCitation> evidence,
    String policyId,
    String policyVersion,
    Recommendation recommendation) {}
