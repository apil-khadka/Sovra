package dev.sovra.issuance;

import com.nimbusds.jose.crypto.impl.ECDSA;
import dev.sovra.trust.TrustSnapshotProvider;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.ObjectMapper;

/**
 * TEST DOUBLE — holds BOTH synthetic private keys (scalars 1 and 3) in one
 * JVM so single-context harness tests can exercise dual-issuer issuance and
 * verification end to end. This is explicitly NOT independent authority:
 * production and demo deployments use per-node single-issuer
 * {@link LocalDevSigner} instances ({@code local-issuer=synth-1} on node A,
 * {@code synth-2} on node B) with separate configs, and sovereignty needs
 * separate databases plus orchestration outside the backend. Every signing
 * call still re-authorizes against the signing-key registry and the active
 * trust snapshot, exactly like the single-issuer signer.
 */
public final class DualIssuerTestDouble implements IssuerSigner {

  private final KeyRef first = new KeyRef(LocalDevSigner.ISSUER_ID, "synth-1", 1);
  private final KeyRef second =
      new KeyRef(LocalDevSigner.SECOND_ISSUER_ID, "synth-2", 1);
  private final ECPrivateKey firstKey;
  private final ECPrivateKey secondKey;
  private final JdbcTemplate global;
  private final TrustSnapshotProvider snapshots;
  private final Clock clock;

  public DualIssuerTestDouble(
      DataSource globalDataSource,
      TrustSnapshotProvider snapshots,
      ObjectMapper mapper,
      Clock clock) throws Exception {
    this.global = new JdbcTemplate(globalDataSource);
    this.snapshots = snapshots;
    this.clock = clock;
    ECParameterSpec params = dev.sovra.crypto.P256.params();
    KeyFactory factory = KeyFactory.getInstance("EC");
    this.firstKey =
        (ECPrivateKey) factory.generatePrivate(new ECPrivateKeySpec(BigInteger.ONE, params));
    this.secondKey = (ECPrivateKey) factory.generatePrivate(
        new ECPrivateKeySpec(BigInteger.valueOf(3), params));
    register(mapper, params);
  }

  private void register(ObjectMapper mapper, ECParameterSpec params) throws Exception {
    ECPoint secondPoint = addPoint(
        doublePoint(params.getGenerator(), params), params.getGenerator(), params);
    registerOne(mapper, first, params.getGenerator());
    registerOne(mapper, second, secondPoint);
  }

  private void registerOne(ObjectMapper mapper, KeyRef ref, ECPoint point) throws Exception {
    String jwk = mapper.writeValueAsString(Map.of(
        "kty", "EC",
        "crv", "P-256",
        "x", dev.sovra.crypto.P256.base64UrlUnsigned(point.getAffineX()),
        "y", dev.sovra.crypto.P256.base64UrlUnsigned(point.getAffineY()),
        "kid", ref.keyId()));
    global.update(
        "INSERT INTO issuer_signing_key (issuer_id, key_id, key_version, public_key_jwk, status)"
            + " VALUES (?, ?, ?, ?::jsonb, 'ACTIVE') ON CONFLICT DO NOTHING",
        ref.issuerId(), ref.keyId(), ref.keyVersion(), jwk);
    List<String> stored = global.query(
        "SELECT public_key_jwk::text FROM issuer_signing_key"
            + " WHERE issuer_id = ? AND key_id = ? AND key_version = ?",
        (rs, row) -> rs.getString(1),
        ref.issuerId(), ref.keyId(), ref.keyVersion());
    if (stored.size() != 1 || !mapper.readTree(stored.get(0)).equals(mapper.readTree(jwk))) {
      throw new IllegalStateException(
          "signing-key registry names a different key for " + ref.encode());
    }
  }

  @Override
  public byte[] sign(KeyRef ref, byte[] payload, String aad) {
    ECPrivateKey key;
    if (first.equals(ref)) {
      key = firstKey;
    } else if (second.equals(ref)) {
      key = secondKey;
    } else {
      throw new SigningRefusedException("unknown signing key");
    }
    AadContext.Parsed context = AadContext.parse(aad);
    if (!ref.issuerId().equals(context.issuer())
        || !ref.encode().equals(context.key())
        || !"issuance".equals(context.purpose())) {
      throw new SigningRefusedException("call context does not name this issuance call");
    }
    if (!dev.sovra.trust.IssuerKeys.active(global, ref.issuerId(), ref.keyId(), ref.keyVersion())) {
      throw new SigningRefusedException("signing key is not active");
    }
    Instant now = clock.instant();
    boolean authorized = snapshots.current().map(snapshot -> snapshot.issuers().stream()
            .anyMatch(issuer -> ref.issuerId().equals(issuer.issuerId())
                && ref.keyId().equals(issuer.keyId())
                && ref.keyVersion() == issuer.keyVersion()
                && dev.sovra.trust.IssuerKeys.usable(issuer, now)))
        .orElse(false);
    if (!authorized) {
      throw new SigningRefusedException("active trust snapshot does not authorize this key");
    }
    try {
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initSign(key);
      signature.update(payload);
      return ECDSA.transcodeSignatureToConcat(signature.sign(), 64);
    } catch (Exception e) {
      throw new SigningRefusedException("signing failed");
    }
  }

  private static ECPoint doublePoint(ECPoint p, ECParameterSpec params) {
    BigInteger prime =
        ((java.security.spec.ECFieldFp) params.getCurve().getField()).getP();
    BigInteger a = params.getCurve().getA();
    BigInteger x = p.getAffineX();
    BigInteger y = p.getAffineY();
    BigInteger slope = x.multiply(x).multiply(BigInteger.valueOf(3)).add(a)
        .multiply(y.multiply(BigInteger.TWO).modInverse(prime)).mod(prime);
    BigInteger rx = slope.multiply(slope).subtract(x.multiply(BigInteger.TWO)).mod(prime);
    BigInteger ry = slope.multiply(x.subtract(rx)).subtract(y).mod(prime);
    return new ECPoint(rx, ry);
  }

  private static ECPoint addPoint(ECPoint p, ECPoint q, ECParameterSpec params) {
    BigInteger prime =
        ((java.security.spec.ECFieldFp) params.getCurve().getField()).getP();
    BigInteger slope = q.getAffineY().subtract(p.getAffineY())
        .multiply(q.getAffineX().subtract(p.getAffineX()).modInverse(prime)).mod(prime);
    BigInteger rx = slope.multiply(slope)
        .subtract(p.getAffineX()).subtract(q.getAffineX()).mod(prime);
    BigInteger ry = slope.multiply(p.getAffineX().subtract(rx))
        .subtract(p.getAffineY()).mod(prime);
    return new ECPoint(rx, ry);
  }
}
