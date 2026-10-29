package dev.sovra.audit;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Opaque keyset cursor for audit pages (SOV-015, IF-11). Encodes the
 * {@code (occurred_at, id)} position of the last row on the previous
 * page; decoding rejects anything that is not exactly that shape.
 * Cursors carry no authority: tenant filtering applies first, so a
 * cursor minted for another tenant only narrows, never widens.
 */
public record AuditCursor(Instant occurredAt, UUID id) {

  /** Encodes a page position from a listed row's occurredAt/id strings. */
  public static String encode(String occurredAt, String id) {
    String raw = occurredAt + "|" + id;
    return Base64.getUrlEncoder().withoutPadding()
        .encodeToString(raw.getBytes(StandardCharsets.UTF_8));
  }

  /** Decodes an untrusted cursor parameter, rejecting malformed values. */
  public static AuditCursor decode(String cursor) {
    try {
      String raw =
          new String(
              Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
      int sep = raw.indexOf('|');
      if (sep < 0 || raw.indexOf('|', sep + 1) >= 0) {
        throw new AuditCursorException("malformed audit cursor");
      }
      return new AuditCursor(
          Instant.parse(raw.substring(0, sep)), UUID.fromString(raw.substring(sep + 1)));
    } catch (java.time.DateTimeException | IllegalArgumentException e) {
      throw new AuditCursorException("malformed audit cursor");
    }
  }
}
