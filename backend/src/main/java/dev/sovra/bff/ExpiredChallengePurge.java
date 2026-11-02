package dev.sovra.bff;

import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Reaps expired unlock challenges (PROD-003/PROD-010). The delete is
 * idempotent, so every replica may run it; expired rows are already
 * unconsumable, and the reap only bounds table growth.
 */
@Component
public class ExpiredChallengePurge {

  private static final Logger log = LoggerFactory.getLogger(ExpiredChallengePurge.class);

  private final ChallengeStore challenges;
  private final Clock clock;

  public ExpiredChallengePurge(ChallengeStore challenges, Clock clock) {
    this.challenges = challenges;
    this.clock = clock;
  }

  @Scheduled(cron = "0 */5 * * * *")
  public void purge() {
    int removed = challenges.deleteExpired(clock.instant());
    if (removed > 0) {
      log.info("reaped {} expired holder-unlock challenges", removed);
    }
  }
}
