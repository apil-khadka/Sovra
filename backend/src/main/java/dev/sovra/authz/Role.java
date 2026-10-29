package dev.sovra.authz;

import java.util.HashSet;
import java.util.Set;

/**
 * The closed set of Sovra roles. Roles were plain strings in the
 * authorization map, the BFF trust registry, and the {@code text[]}
 * columns — so a typo either silently broke access or, in the BFF
 * privileged-roles list, silently skipped the hardware-AMR gate.
 * Parsing ({@link #from}) and Spring enum binding fail fast on
 * anything outside this set; the database CHECK (V18) closes the
 * last door at rest.
 *
 * <p>Declaration order is alphabetical: wire output that sorts roles
 * renders byte-identically to the old string sorting.
 */
public enum Role {
  AUDIT_READER,
  ISSUER_OPS,
  RP_CLIENT,
  TENANT_MEMBER,
  TRUST_ADMIN;

  /** Parses a stored or configured role name, failing fast on unknown values. */
  public static Role from(String name) {
    try {
      return Role.valueOf(name);
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new IllegalArgumentException("unknown role: " + name);
    }
  }

  /** Parses a stored role array, failing fast on the first unknown value. */
  public static Set<Role> parseAll(String[] names) {
    Set<Role> parsed = new HashSet<>();
    for (String name : names) {
      parsed.add(from(name));
    }
    return parsed;
  }
}
