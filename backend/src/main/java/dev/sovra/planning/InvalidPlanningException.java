package dev.sovra.planning;

/** Invalid planning intent or candidate. Fails before any model call. Maps to 400. */
public class InvalidPlanningException extends RuntimeException {

  public InvalidPlanningException(String message) {
    super(message);
  }
}
