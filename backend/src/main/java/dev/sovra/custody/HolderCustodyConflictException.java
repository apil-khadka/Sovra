package dev.sovra.custody;

/**
 * Double report, double recovery, or recovery on a stale case;
 * rendered as 409. Compromise ends authority once; recovery
 * completes once.
 */
public class HolderCustodyConflictException extends RuntimeException {

  public HolderCustodyConflictException(String message) {
    super(message);
  }
}
