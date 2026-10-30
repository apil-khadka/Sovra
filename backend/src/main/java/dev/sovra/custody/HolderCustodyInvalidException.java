package dev.sovra.custody;

/** Malformed custody input or recovery proof; rendered as 400. */
public class HolderCustodyInvalidException extends RuntimeException {

  public HolderCustodyInvalidException(String message) {
    super(message);
  }
}
