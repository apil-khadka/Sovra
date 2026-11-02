package dev.sovra.bff;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * Database-backed {@link ChallengeStore}. Consume is a single
 * conditional {@code DELETE ... RETURNING}: the database, not the
 * replica, decides which of two simultaneous submissions wins.
 * Uses the plain datasource — challenges are keyed by an
 * unguessable value plus the authenticated membership id, not by
 * tenant row policy.
 */
@Repository
public class JdbcChallengeStore implements ChallengeStore {

  private final JdbcTemplate jdbc;

  public JdbcChallengeStore(DataSource globalDataSource) {
    this.jdbc = new JdbcTemplate(globalDataSource);
  }

  @Override
  public boolean issue(UUID membershipId, String challenge, Instant expiresAt) {
    try {
      jdbc.update(
          "INSERT INTO holder_unlock_challenge (challenge, membership_id, expires_at)"
              + " VALUES (?, ?, ?)",
          challenge,
          membershipId,
          java.sql.Timestamp.from(expiresAt));
      return true;
    } catch (DuplicateKeyException e) {
      return false;
    }
  }

  @Override
  public boolean consume(UUID membershipId, String challenge, Instant now) {
    List<String> consumed =
        jdbc.query(
            "DELETE FROM holder_unlock_challenge"
                + " WHERE challenge = ? AND membership_id = ? AND expires_at > ?"
                + " RETURNING challenge",
            (rs, row) -> rs.getString("challenge"),
            challenge,
            membershipId,
            java.sql.Timestamp.from(now));
    return consumed.size() == 1;
  }

  @Override
  public int deleteExpired(Instant now) {
    // PROD-010: bounded batch in expiry order; a backlog drains
    // over successive 5-minute runs instead of one long lock.
    return jdbc.update(
        "DELETE FROM holder_unlock_challenge WHERE challenge IN ("
            + " SELECT challenge FROM holder_unlock_challenge"
            + " WHERE expires_at <= ? ORDER BY expires_at LIMIT 1000)",
        java.sql.Timestamp.from(now));
  }

  @Override
  public void deleteForMember(UUID membershipId) {
    jdbc.update("DELETE FROM holder_unlock_challenge WHERE membership_id = ?", membershipId);
  }
}
