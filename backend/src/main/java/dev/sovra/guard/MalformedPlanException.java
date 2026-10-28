package dev.sovra.guard;

/**
 * Structurally incompatible plan, context, or policy input. Carries no
 * caller content: messages stay static so untrusted bytes never flow
 * into logs or verdicts unfiltered.
 */
public class MalformedPlanException extends RuntimeException {

  public MalformedPlanException() {
    super("plan input does not match the guard schema");
  }
}
