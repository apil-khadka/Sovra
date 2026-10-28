package dev.sovra.guard;

/** Planner-reported path state. Anything but CANDIDATE_ONLY routes to manual review. */
public enum Recommendation {
  CANDIDATE_ONLY,
  NO_PATH,
  MANUAL_REVIEW
}
