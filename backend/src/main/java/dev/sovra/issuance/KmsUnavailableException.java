package dev.sovra.issuance;

/** Production signing backend unavailable; rendered as HTTP 503. */
public class KmsUnavailableException extends RuntimeException {

  public KmsUnavailableException(String message) {
    super(message);
  }
}
