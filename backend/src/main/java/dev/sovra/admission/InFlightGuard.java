package dev.sovra.admission;

import java.util.concurrent.Semaphore;
import org.springframework.stereotype.Component;

/**
 * Per-replica in-flight ceilings (PROD-006). Rate buckets bound
 * arrivals over time; these semaphores bound simultaneous expensive
 * work so one slow dependency cannot pile up unbounded threads
 * behind it. Admission is non-blocking: a full group fails fast
 * with 503 instead of queueing.
 *
 * <p>Per-replica by design: a fleet-wide exact count would need a
 * distributed semaphore, while N replicas × permits is already a
 * hard fleet ceiling operators can reason about.
 */
@Component
public class InFlightGuard {

  public enum Group {
    DEFAULT,
    CRYPTO,
    UPLOAD
  }

  private final Semaphore standard;
  private final Semaphore crypto;
  private final Semaphore upload;

  public InFlightGuard(AdmissionProperties properties) {
    this.standard = new Semaphore(properties.inFlight().defaultPermits());
    this.crypto = new Semaphore(properties.inFlight().cryptoPermits());
    this.upload = new Semaphore(properties.inFlight().uploadPermits());
  }

  /** One permit per request, released in a finally block by the caller. */
  public boolean tryEnter(Group group) {
    return semaphore(group).tryAcquire();
  }

  public void leave(Group group) {
    semaphore(group).release();
  }

  private Semaphore semaphore(Group group) {
    return switch (group) {
      case CRYPTO -> crypto;
      case UPLOAD -> upload;
      case DEFAULT -> standard;
    };
  }

  /** Classifies a request path. BFF twins share their machine-chain group. */
  public static Group groupFor(String path) {
    String plain = path.startsWith("/api/bff/") ? "/api/" + path.substring("/api/bff/".length()) : path;
    if (plain.startsWith("/api/verification/")
        || plain.startsWith("/api/issuance/")
        || plain.startsWith("/api/consent/")
        || plain.startsWith("/api/vci/")
        || plain.startsWith("/api/vp/")
        || plain.startsWith("/api/holder-keys/")) {
      return Group.CRYPTO;
    }
    if (plain.startsWith("/api/vault/")
        || plain.startsWith("/api/quarantine/")
        || plain.startsWith("/api/extraction/")
        || plain.startsWith("/api/enrollments/")) {
      return Group.UPLOAD;
    }
    return Group.DEFAULT;
  }
}
