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
 * G1 software signing double (SOV-004 section 2). Each node serves exactly
 * ONE synthetic issuer, chosen by {@code sovra.synthetic-issuers.local-issuer}
 * ({@code synth-1} by default, {@code synth-2} for the second node):
 *
 * <ul>
 *   <li>{@code synth-1}: P-256 scalar 1 (public half is the generator point),
 *   issuer {@code https://sovra.example/issuers/synth-1}, key
 *   {@code synth-1:v1}.</li>
 *   <li>{@code synth-2}: P-256 scalar 3 (public half is 3G), issuer
 *   {@code https://sovra.example/issuers/synth-2}, key {@code synth-2:v1}.</li>
 * </ul>
 *
 * <p>Private halves live in memory only, never persisted or exported, armed
 * only by both synthetic flags. A node holding scalar 1 REFUSES
 * {@code synth-2} signing requests and vice versa — cross-signing denial is
 * a committed regression, not a fallback. Anyone can recompute these keys,
 * which is exactly why they must never leave synthetic use.
 *
 * <p>Production uses {@link KmsSigner}. Every call re-authorizes the key
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

  public static final String SECOND_ISSUER_ID = "https://sovra.example/issuers/synth-2";
  static final String SECOND_KEY_ID = "synth-2";
  static final int SECOND_KEY_VERSION = 1;

  static final String CURVE = "P-256";

  private final KeyRef keyRef;
  private final String issuerId;
  private final String keyId;
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
      @Value("${sovra.synthetic-issuers.acknowledge-non-production:false}") boolean acknowledged,
      @Value("${sovra.synthetic-issuers.local-issuer:synth-1}") String localIssuer)
      throws Exception {
    if (!enabled || !acknowledged) {
      throw new IllegalStateException(
          "LocalDevSigner needs both sovra.synthetic-issuers.enabled and"
              + " sovra.synthetic-issuers.acknowledge-non-production set to true;"
              + " production must use KmsSigner");
    }
    String selection = localIssuer == null ? "" : localIssuer.trim();
    BigInteger scalar;
    ECPoint point;
    ECParameterSpec params = dev.sovra.crypto.P256.params();
    KeyFactory factory = KeyFactory.getInstance("EC");
    if ("synth-1".equals(selection) || selection.isEmpty()) {
      this.issuerId = ISSUER_ID;
      this.keyId = KEY_ID;
      this.keyRef = new KeyRef(ISSUER_ID, KEY_ID, KEY_VERSION);
      scalar = BigInteger.ONE;
      point = params.getGenerator();
    } else if ("synth-2".equals(selection)) {
      this.issuerId = SECOND_ISSUER_ID;
      this.keyId = SECOND_KEY_ID;
      this.keyRef = new KeyRef(SECOND_ISSUER_ID, SECOND_KEY_ID, SECOND_KEY_VERSION);
      scalar = BigInteger.valueOf(3);
      point = addPoint(doublePoint(params.getGenerator(), params), params.getGenerator(), params);
    } else {
      throw new IllegalStateException(
          "sovra.synthetic-issuers.local-issuer must be synth-1 or synth-2, got: " + localIssuer);
    }
    this.global = new JdbcTemplate(globalDataSource);
    this.snapshots = snapshots;
    this.mapper = mapper;
    this.clock = clock;
    this.privateKey =
        (ECPrivateKey) factory.generatePrivate(new ECPrivateKeySpec(scalar, params));
    this.publicPoint = point;
    register();
  }

  /** Registers the public half; refuses if the registry names another key. */
  private void register() throws Exception {
    String jwk = publicJwk();
    global.update(
        "INSERT INTO issuer_signing_key (issuer_id, key_id, key_version, public_key_jwk, status)"
            + " VALUES (?, ?, ?, ?::jsonb, 'ACTIVE') ON CONFLICT DO NOTHING",
        issuerId,
        keyId,
        keyRef.keyVersion(),
        jwk);
    List<String> stored =
        global.query(
            "SELECT public_key_jwk::text FROM issuer_signing_key"
                + " WHERE issuer_id = ? AND key_id = ? AND key_version = ?",
            (rs, row) -> rs.getString(1),
            issuerId,
            keyId,
            keyRef.keyVersion());
    if (stored.size() != 1 || !sameJwk(stored.get(0), jwk)) {
      throw new IllegalStateException(
          "signing-key registry names a different key for " + keyRef.encode() + "; refusing to serve");
    }
    log.warn(
        "synthetic issuer active: {} key {} is a NON-PRODUCTION double; signatures are"
            + " labelled synthetic and must never verify in production."
            + " This node serves ONLY this issuer and refuses all other signing keys.",
        issuerId,
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
            "kid", keyId);
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
    if (!issuerId.equals(context.issuer())) {
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
    return dev.sovra.trust.IssuerKeys.active(global, issuerId, keyId, keyRef.keyVersion());
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
                            issuerId.equals(issuer.issuerId())
                                && keyId.equals(issuer.keyId())
                                && keyRef.keyVersion() == issuer.keyVersion()
                                && dev.sovra.trust.IssuerKeys.usable(issuer, now)))
        .orElse(false);
  }

  /** P-256 point doubling (same arithmetic as the OpenID verifier key). */
  private static ECPoint doublePoint(ECPoint p, ECParameterSpec params) {
    BigInteger prime =
        ((java.security.spec.ECFieldFp) params.getCurve().getField()).getP();
    BigInteger a = params.getCurve().getA();
    BigInteger x = p.getAffineX();
    BigInteger y = p.getAffineY();
    BigInteger slope =
        x.multiply(x)
            .multiply(BigInteger.valueOf(3))
            .add(a)
            .multiply(y.multiply(BigInteger.TWO).modInverse(prime))
            .mod(prime);
    BigInteger rx = slope.multiply(slope).subtract(x.multiply(BigInteger.TWO)).mod(prime);
    BigInteger ry = slope.multiply(x.subtract(rx)).subtract(y).mod(prime);
    return new ECPoint(rx, ry);
  }

  /** P-256 point addition for distinct points (scalar 3 = 2G + G). */
  private static ECPoint addPoint(ECPoint p, ECPoint q, ECParameterSpec params) {
    BigInteger prime =
        ((java.security.spec.ECFieldFp) params.getCurve().getField()).getP();
    BigInteger slope =
        q.getAffineY().subtract(p.getAffineY())
            .multiply(q.getAffineX().subtract(p.getAffineX()).modInverse(prime))
            .mod(prime);
    BigInteger rx = slope.multiply(slope)
        .subtract(p.getAffineX()).subtract(q.getAffineX()).mod(prime);
    BigInteger ry = slope.multiply(p.getAffineX().subtract(rx))
        .subtract(p.getAffineY()).mod(prime);
    return new ECPoint(rx, ry);
  }
}
