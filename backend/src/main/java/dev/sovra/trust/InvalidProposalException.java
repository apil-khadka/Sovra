package dev.sovra.trust;

/** Proposal content failed SOV-001 profile validation; rendered as HTTP 400. */
public class InvalidProposalException extends RuntimeException {

  public InvalidProposalException(String message) {
    super(message);
  }
}
