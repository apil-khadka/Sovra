package dev.sovra.bff;

/** Holder self-reads without a live key unlock. Maps to 403. */
public class HolderLockedException extends RuntimeException {

  public HolderLockedException() {
    super("holder key is not unlocked in this session");
  }
}
