package dev.sovra.issuance;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Structured signer call context (SOV-004 section 3). The wire form
 * stays the canonical {@code k=v;k=v} string the {@link IssuerSigner}
 * interface carries, but no code hand-formats or hand-parses it:
 * construction rejects values that would break the framing
 * ({@code ;}, {@code =}, blanks), so a crafted issuer id can never
 * inject fields, and parsing refuses duplicate keys instead of
 * last-wins. Untrusted parsed fields are kept in a separate type;
 * only complete, validated contexts can be encoded.
 */
public record AadContext(
    String issuer, String key, String credential, String purpose, String schema) {

  public AadContext {
    framed("issuer", issuer);
    framed("key", key);
    framed("credential", credential);
    framed("purpose", purpose);
    framed("schema", schema);
  }

  /** Issuance call context; the only purpose the signers honor. */
  public static AadContext issuance(String issuer, String key, String credential, String schema) {
    return new AadContext(issuer, key, credential, "issuance", schema);
  }

  private static String framed(String field, String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("aad field '" + field + "' is required");
    }
    if (value.indexOf(';') >= 0 || value.indexOf('=') >= 0) {
      throw new IllegalArgumentException("aad field '" + field + "' breaks framing");
    }
    return value;
  }

  /** Canonical wire form. */
  public String encode() {
    return "issuer=" + issuer + ";key=" + key + ";credential=" + credential
        + ";purpose=" + purpose + ";schema=" + schema;
  }

  /**
   * Strict parse. Any malformed segment voids the call; duplicate
   * keys refuse instead of last-wins, so an injected second
   * {@code issuer=} can never override the first.
   */
  static Parsed parse(String aad) {
    Map<String, String> fields = new LinkedHashMap<>();
    if (aad == null || aad.isBlank()) {
      throw new SigningRefusedException("call context is malformed");
    }
    for (String segment : aad.split(";", -1)) {
      int eq = segment.indexOf('=');
      if (eq <= 0 || eq == segment.length() - 1) {
        throw new SigningRefusedException("call context is malformed");
      }
      String field = segment.substring(0, eq);
      if (fields.containsKey(field)) {
        throw new SigningRefusedException("call context repeats a field");
      }
      fields.put(field, segment.substring(eq + 1));
    }
    return new Parsed(
        fields.get("issuer"),
        fields.get("key"),
        fields.get("credential"),
        fields.get("purpose"),
        fields.get("schema"));
  }

  /** Untrusted fields; missing values fail the signer's domain checks. */
  record Parsed(String issuer, String key, String credential, String purpose, String schema) {}
}
