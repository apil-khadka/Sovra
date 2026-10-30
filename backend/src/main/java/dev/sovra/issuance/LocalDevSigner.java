package dev.sovra.issuance;

import com.nimbusds.jose.crypto.impl.ECDSA;
import dev.sovra.trust.TrustSnapshotProvider;
import java.math.BigInteger;
import java.time.Clock;
import java.time.Instant;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

/**
 * G1 software signing double (SOV-004 section 2). The private key is the
 * P-256 scalar 1 — the most obviously non-secret key imaginable — held in
 * memory only, never persisted or exported. It signs the synthetic issuer
 * only, and only while both arming flags are set:
 *
 * <ul>
 *   <li>{@code sovra.synthetic-issuers.enabled=true}</li>
 *   <li>{@code sovra.synthetic-issuers.acknowledge-non-production=true}</li>
 * </ul>
 *
 * Production uses {@link KmsSigner}. Every call re-authorizes the key
 * against the signing-key registry and the active trust snapshot.
 */
@Service
@DependsOnDatabaseInitialization
@ConditionalOnProperty(name = "sovra.signer", havingValue = "local-dev", matchIfMissing = true)
public class LocalDevSigner implements IssuerSigner {

  private static final Logger log = LoggerFactory.getLogger(LocalDevSigner.class);

  public static final String ISSUER_ID = "https://sovra.example/issuers/synth-1";
  static final String KEY_ID = "synth-1";
  static final int KEY_VERSION = 1;
  static final String CURVE = "P-256";

  private final KeyRef keyRef = new KeyRef(ISSUER_ID, KEY_ID, KEY_VERSION);
  private final ECPrivateKey privateKey;
  private final ECPoint publicPoint;
  private final JdbcTemplate global;
  private final TrustSnapshotProvider snapshots;
  private final ObjectMapper mapper;
  private final Clock clock;

  public LocalDevSigner(
      DataSource globalDataSource,
      TrustSnapshotProvider snapshots,
      ObjectMapper mapper,
      Clock clock,
      @Value("${sovra.synthetic-issuers.enabled:false}") boolean enabled,
      @Value("${sovra.synthetic-issuers.acknowledge-non-production:false}") boolean acknowledged)
      throws Exception {
    if (!enabled || !acknowledged) {
      throw new IllegalStateException(
          "LocalDevSigner needs both sovra.synthetic-issuers.enabled and"
              + " sovra.synthetic-issuers.acknowledge-non-production set to true;"
              + " production must use KmsSigner");
    }
    this.global = new JdbcTemplate(globalDataSource);
    this.snapshots = snapshots;
    this.mapper = mapper;
    this.clock = clock;
    KeyFactory factory = KeyFactory.getInstance("EC");
    ECParameterSpec params = dev.sovra.crypto.P256.params();
    // Scalar 1: public key is the generator point. Anyone can recompute
    // this key, which is exactly why it must never leave synthetic use.
    this.privateKey =
        (ECPrivateKey) factory.generatePrivate(new ECPrivateKeySpec(BigInteger.ONE, params));
    this.publicPoint = params.getGenerator();
    register();
  }

  /** Registers the public half; refuses if the registry names another key. */
  private void register() throws Exception {
    String jwk = publicJwk();
    global.update(
        "INSERT INTO issuer_signing_key (issuer_id, key_id, key_version, public_key_jwk, status)"
            + " VALUES (?, ?, ?, ?::jsonb, 'ACTIVE') ON CONFLICT DO NOTHING",
        ISSUER_ID,
        KEY_ID,
        KEY_VERSION,
        jwk);
    List<String> stored =
        global.query(
            "SELECT public_key_jwk::text FROM issuer_signing_key"
                + " WHERE issuer_id = ? AND key_id = ? AND key_version = ?",
            (rs, row) -> rs.getString(1),
            ISSUER_ID,
            KEY_ID,
            KEY_VERSION);
    if (stored.size() != 1 || !sameJwk(stored.get(0), jwk)) {
      throw new IllegalStateException(
          "signing-key registry names a different key for " + keyRef.encode() + "; refusing to serve");
    }
    log.warn(
        "synthetic issuer active: {} key {} is a NON-PRODUCTION double; signatures are"
            + " labelled synthetic and must never verify in production",
        ISSUER_ID,
        keyRef.encode());
  }

  private boolean sameJwk(String a, String b) throws Exception {
    return mapper.readTree(a).equals(mapper.readTree(b));
  }

  /** Public JWK (no private material; there is no private-key accessor). */
  private String publicJwk() {
    Map<String, String> jwk =
        Map.of(
            "kty", "EC",
            "crv", CURVE,
            "x", dev.sovra.crypto.P256.base64UrlUnsigned(publicPoint.getAffineX()),
            "y", dev.sovra.crypto.P256.base64UrlUnsigned(publicPoint.getAffineY()),
            "kid", KEY_ID);
    try {
      return mapper.writeValueAsString(jwk);
    } catch (tools.jackson.core.JacksonException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public byte[] sign(KeyRef ref, byte[] payload, String aad) {
    if (!keyRef.equals(ref)) {
      throw new SigningRefusedException("unknown signing key");
    }
    // Exact field match, never substring: an embedded "issuer=<ours>"
    // inside another field must not satisfy the check (SOV-040).
    AadContext.Parsed context = AadContext.parse(aad);
    if (!ISSUER_ID.equals(context.issuer())) {
      throw new SigningRefusedException("call context does not name this issuer");
    }
    if (!keyRef.encode().equals(context.key())) {
      throw new SigningRefusedException("call context does not name this key");
    }
    if (!"issuance".equals(context.purpose())) {
      throw new SigningRefusedException("call context is not an issuance call");
    }
    if (!registryActive()) {
      throw new SigningRefusedException("signing key is not active");
    }
    if (!snapshotAuthorizes()) {
      throw new SigningRefusedException("active trust snapshot does not authorize this key");
    }
    try {
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initSign(privateKey);
      signature.update(payload);
      return ECDSA.transcodeSignatureToConcat(signature.sign(), 64);
    } catch (Exception e) {
      throw new SigningRefusedException("signing failed");
    }
  }

  private boolean registryActive() {
    return dev.sovra.trust.IssuerKeys.active(global, ISSUER_ID, KEY_ID, KEY_VERSION);
  }

  private boolean snapshotAuthorizes() {
    Instant now = clock.instant();
    return snapshots
        .current()
        .map(
            snapshot ->
                snapshot.issuers().stream()
                    .anyMatch(
                        issuer ->
                            ISSUER_ID.equals(issuer.issuerId())
                                && KEY_ID.equals(issuer.keyId())
                                && KEY_VERSION == issuer.keyVersion()
                                && dev.sovra.trust.IssuerKeys.usable(issuer, now)))
        .orElse(false);
  }

}
