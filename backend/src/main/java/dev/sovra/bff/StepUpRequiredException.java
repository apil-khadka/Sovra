package dev.sovra.bff;

/** The session's authentication is too old or too weak for a privileged decision. */
public class StepUpRequiredException extends RuntimeException {
  StepUpRequiredException(String message) {
    super(message);
  }
}
