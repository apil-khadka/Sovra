package dev.sovra.bff;

/** Holder unlock failures: expired challenges, bad keys, invalid proofs. Maps to 400. */
public class HolderUnlockException extends RuntimeException {

  public HolderUnlockException(String message) {
    super(message);
  }
}
