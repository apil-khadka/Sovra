package dev.sovra.admission;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Admission budgets (PROD-006). Every value is tunable per
 * deployment; the defaults below are the approved starting point
 * from the capacity contract, sized so ordinary console, SDK, and
 * probe traffic never notices them while floods and hot tenants
 * hit explicit 429s with retry guidance.
 *
 * <p>Rates are tokens per second, capacities are burst sizes. A
 * request costs one token from each bucket applied to it. Boxed
 * fields let operators override one value without restating its
 * siblings.
 */
@ConfigurationProperties(prefix = "sovra.admission")
public record AdmissionProperties(
    Bucket principal,
    Bucket tenant,
    Bucket anonymousLogin,
    Bucket anonymousProtocol,
    Bucket probeReady,
    Bucket probeHealth,
    InFlight inFlight,
    Bodies bodies) {

  public record Bucket(Double capacity, Double ratePerSecond) {
    public Bucket {
      if (capacity == null) {
        capacity = 300.0;
      }
      if (ratePerSecond == null) {
        ratePerSecond = 10.0;
      }
    }
  }

  public record InFlight(Integer defaultPermits, Integer cryptoPermits, Integer uploadPermits) {
    public InFlight {
      if (defaultPermits == null) {
        defaultPermits = 200;
      }
      if (cryptoPermits == null) {
        cryptoPermits = 50;
      }
      if (uploadPermits == null) {
        uploadPermits = 20;
      }
    }
  }

  public record Bodies(Long defaultMaxBytes, Long documentMaxBytes) {
    public Bodies {
      if (defaultMaxBytes == null) {
        defaultMaxBytes = 2L << 20;
      }
      if (documentMaxBytes == null) {
        documentMaxBytes = 20L << 20;
      }
    }
  }

  public AdmissionProperties {
    if (principal == null) {
      principal = new Bucket(300.0, 10.0);
    }
    if (tenant == null) {
      tenant = new Bucket(1000.0, 50.0);
    }
    if (anonymousLogin == null) {
      anonymousLogin = new Bucket(100.0, 2.0);
    }
    if (anonymousProtocol == null) {
      anonymousProtocol = new Bucket(200.0, 5.0);
    }
    if (probeReady == null) {
      probeReady = new Bucket(60.0, 2.0);
    }
    if (probeHealth == null) {
      probeHealth = new Bucket(600.0, 20.0);
    }
    if (inFlight == null) {
      inFlight = new InFlight(200, 50, 20);
    }
    if (bodies == null) {
      bodies = new Bodies(2L << 20, 20L << 20);
    }
  }
}
