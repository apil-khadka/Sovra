package dev.sovra.ops;

import java.security.SecureRandom;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Fleet identity (PROD-011). The instance id names the replica
 * (container hostname by default); the boot id is random per process
 * start, so a restarted replica is distinguishable from a stale one.
 * Both ride on health payloads and on every Micrometer metric tag.
 */
@Component
public class InstanceIdentity {

  private final String instanceId;
  private final String bootId;

  public InstanceIdentity(@Value("${sovra.instance-id}") String instanceId) {
    this.instanceId = instanceId;
    byte[] random = new byte[8];
    new SecureRandom().nextBytes(random);
    StringBuilder boot = new StringBuilder(16);
    for (byte b : random) {
      boot.append(String.format("%02x", b));
    }
    this.bootId = boot.toString();
  }

  public String instanceId() {
    return instanceId;
  }

  public String bootId() {
    return bootId;
  }
}
