package dev.sovra.bff;

import dev.sovra.bff.HolderUnlockService.Unlock;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.jackson.OAuth2ClientJacksonModule;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Session-attribute bytes for the shared JDBC store (PROD-003).
 *
 * <p>Every attribute is a small JSON envelope naming its own type:
 * {@code {"t":"s","v":"..."}}. The registry below is the complete set of
 * types a Sovra session may hold; there is no polymorphic deserialization
 * of any kind, so a hostile or corrupt row can never instantiate an
 * unexpected class. Unknown or unreadable attributes are dropped with a
 * warning — every reader treats a missing attribute as anonymous or
 * locked, so degradation always fails closed.
 */
public class SessionAttributeCodec {

  private static final Logger log = LoggerFactory.getLogger(SessionAttributeCodec.class);

  private final ObjectMapper mapper;

  public SessionAttributeCodec() {
    // Dedicated mapper: the OAuth2 dance module stays out of the
    // API mapper, and API settings stay out of session bytes.
    this.mapper =
        JsonMapper.builder().addModule(new OAuth2ClientJacksonModule()).build();
  }

  /** Serializes one attribute value. Unknown Java types fail fast, never silently. */
  public byte[] encode(Object value) {
    String type;
    if (value instanceof String) {
      type = "s";
    } else if (value instanceof List) {
      type = "sl";
    } else if (value instanceof Unlock) {
      type = "unlock";
    } else if (value instanceof OAuth2AuthorizationRequest) {
      type = "oauth2ar";
    } else {
      throw new IllegalArgumentException(
          "unsupported session attribute type: "
              + (value == null ? "null" : value.getClass().getName()));
    }
    ObjectNode envelope = mapper.createObjectNode();
    envelope.put("t", type);
    envelope.set("v", mapper.valueToTree(value));
    return mapper.writeValueAsBytes(envelope);
  }

  /**
   * Deserializes one attribute value. Returns {@code null} for unknown
   * types and corrupt bytes: the attribute reads as absent, which every
   * session reader treats as anonymous or locked.
   */
  public Object decode(byte[] bytes) {
    JsonNode envelope;
    try {
      envelope = mapper.readTree(bytes);
    } catch (RuntimeException e) {
      log.warn("dropping unreadable session attribute ({} bytes)", bytes.length);
      return null;
    }
    if (!envelope.isObject()
        || !envelope.has("t")
        || !envelope.get("t").isString()
        || !envelope.has("v")) {
      log.warn("dropping malformed session attribute envelope");
      return null;
    }
    String type = envelope.get("t").asString();
    JsonNode value = envelope.get("v");
    try {
      return switch (type) {
        case "s" -> value.isString() ? value.asString() : null;
        case "sl" -> stringList(value);
        case "unlock" -> unlock(value);
        case "oauth2ar" -> mapper.treeToValue(value, OAuth2AuthorizationRequest.class);
        default -> {
          log.warn("dropping session attribute of unknown type '{}'", type);
          yield null;
        }
      };
    } catch (RuntimeException e) {
      // Class name only: Jackson messages can echo the offending
      // value, and session bytes may carry bearer credentials.
      log.warn(
          "dropping undecodable session attribute of type '{}' ({})",
          type, e.getClass().getName());
      log.debug("session attribute decode failure", e);
      return null;
    }
  }

  private Unlock unlock(JsonNode value) {
    Unlock bound = mapper.treeToValue(value, Unlock.class);
    // Jackson coerces sloppy JSON (42 becomes "42"); a grant with
    // no key or no expiry is corrupt, not unlockable.
    if (bound == null || bound.thumbprint() == null || bound.thumbprint().isBlank()
        || bound.expiresAt() == null) {
      return null;
    }
    return bound;
  }

  private static List<String> stringList(JsonNode value) {
    if (!value.isArray()) {
      return null;
    }
    List<String> items = new ArrayList<>();
    for (JsonNode item : value) {
      if (!item.isString()) {
        return null;
      }
      items.add(item.asString());
    }
    return List.copyOf(items);
  }

  /** Test hook: the raw envelope, for asserting JSON (never Java-serialized) bytes. */
  static String envelopeOf(byte[] bytes) {
    return new String(bytes, StandardCharsets.UTF_8);
  }
}
