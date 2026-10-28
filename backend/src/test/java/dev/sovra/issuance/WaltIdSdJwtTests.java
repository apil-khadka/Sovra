package dev.sovra.issuance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import id.walt.sdjwt.SDJwt;
import id.walt.sdjwt.SimpleJWTCryptoProvider;
import id.walt.sdjwt.VerificationResult;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import kotlinx.serialization.json.JsonObject;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * SOV-036 qualification: SD-JWT VC issuance over walt-id, exercised
 * without Spring. Covers the constrained-signer bridge, artifact shape,
 * disclosure integrity (also recomputed independently of walt's walk),
 * the claim allowlist, and Nimbus 10.3 API compatibility against the
 * 10.10 surface walt-id was compiled with.
 */
class WaltIdSdJwtTests {

  static final String ISSUER = "https://sovra.example/issuers/synth-1";
  static final String VCT = "https://sovra.example/vct/adult-status/1";

  private final ObjectMapper mapper = new ObjectMapper();

  /** In-memory constrained signer: authorizes exactly one key, like production. */
  static final class TestSigner implements IssuerSigner {
    final KeyRef ref;
    final ECPrivateKey privateKey;
    KeyRef seenRef;
    String seenAad;
    int calls;

    TestSigner(KeyRef ref, ECPrivateKey privateKey) {
      this.ref = ref;
      this.privateKey = privateKey;
    }

    @Override
    public byte[] sign(KeyRef keyRef, byte[] payload, String aad) {
      calls++;
      seenRef = keyRef;
      seenAad = aad;
      if (!ref.equals(keyRef)) {
        throw new SigningRefusedException("unknown key");
      }
      try {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(payload);
        return ECDSA.transcodeSignatureToConcat(signature.sign(), 64);
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    }
  }

  record Keys(ECPublicKey publicKey, ECPrivateKey privateKey, JsonNode jwk, String thumbprint) {}

  private Keys generateKeys() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair pair = generator.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) pair.getPublic();
    Map<String, String> jwk = new LinkedHashMap<>();
    jwk.put("kty", "EC");
    jwk.put("crv", "P-256");
    jwk.put("x", base64UrlUnsigned(pub.getW().getAffineX()));
    jwk.put("y", base64UrlUnsigned(pub.getW().getAffineY()));
    JsonNode node = mapper.readTree(mapper.writeValueAsString(jwk));
    String thumbprint =
        LocalDevSigner.thumbprint(pub.getW().getAffineX(), pub.getW().getAffineY());
    return new Keys(pub, (ECPrivateKey) pair.getPrivate(), node, thumbprint);
  }

  private static String base64UrlUnsigned(BigInteger value) {
    byte[] raw = value.toByteArray();
    byte[] fixed = new byte[32];
    System.arraycopy(raw, Math.max(0, raw.length - 32), fixed, Math.max(0, 32 - raw.length),
        Math.min(32, raw.length));
    return Base64URL.encode(fixed).toString();
  }

  private IssuanceEvidence evidence(Keys holder) {
    return new IssuanceEvidence(
        UUID.randomUUID(), ISSUER, new KeyRef(ISSUER, "synth-1", 1), VCT,
        Map.of("adultOver18", Boolean.TRUE), holder.thumbprint(),
        Instant.now(), Instant.now().plusSeconds(3600), 1, "/status", holder.jwk());
  }

  @Test
  void roundTripThroughConstrainedSigner() throws Exception {
    Keys issuer = generateKeys();
    Keys holder = generateHolderKeys();
    TestSigner signer = new TestSigner(new KeyRef(ISSUER, "synth-1", 1), issuer.privateKey());
    WaltIdSdJwtVcEncoder encoder = new WaltIdSdJwtVcEncoder(signer);

    IssuanceEvidence input = evidence(holder);
    CredentialEncoder.EncodedCredential encoded = encoder.encode(input);

    // Constrained boundary: exactly one signing call, authorized key,
    // call context naming issuer and credential.
    assertThat(signer.calls).isEqualTo(1);
    assertThat(signer.seenRef).isEqualTo(new KeyRef(ISSUER, "synth-1", 1));
    assertThat(signer.seenAad).contains("issuer=" + ISSUER);
    assertThat(signer.seenAad).contains("credential=" + input.credentialId());

    // Shape: issuer-signed JWT plus disclosures, dc+sd-jwt type.
    assertThat(encoded.artifact()).contains("~");
    SDJwt parsed = SDJwt.Companion.parse(encoded.artifact());
    JsonObject header = parsed.getHeader();
    assertThat(header.get("typ").toString()).contains(WaltIdSdJwtVcEncoder.TYP);
    assertThat(header.get("kid").toString()).contains("synth-1");

    // walt-id verification path with the issuer key.
    SimpleJWTCryptoProvider verifier = new SimpleJWTCryptoProvider(
        JWSAlgorithm.ES256, null, new ECDSAVerifier(issuer.publicKey()));
    VerificationResult<SDJwt> result = parsed.verify(verifier, "synth-1");
    assertThat(result.getSignatureVerified()).isTrue();
    assertThat(result.getDisclosuresVerified()).isTrue();

    // Resolved claims carry the allowlisted value.
    String resolved = parsed.getSdPayload().getFullPayload().toString();
    JsonNode full = mapper.readTree(resolved);
    assertThat(full.get("iss").asString()).isEqualTo(ISSUER);
    assertThat(full.get("vct").asString()).isEqualTo(VCT);
    assertThat(full.get("jti").asString()).isEqualTo(input.credentialId().toString());
    assertThat(full.get("claims").get("adultOver18").asBoolean()).isTrue();
  }

  @Test
  void disclosureDigestsRecomputeIndependently() throws Exception {
    Keys issuer = generateKeys();
    Keys holder = generateHolderKeys();
    TestSigner signer = new TestSigner(new KeyRef(ISSUER, "synth-1", 1), issuer.privateKey());
    CredentialEncoder.EncodedCredential encoded =
        new WaltIdSdJwtVcEncoder(signer).encode(evidence(holder));

    // Independent of walt's walk: JDK SHA-256 over each disclosure must
    // appear in the _sd array of the undisclosed payload.
    String[] parts = encoded.artifact().split("~");
    assertThat(parts.length).isGreaterThan(1);
    String jwtBody = new String(
        Base64URL.from(parts[0].split("\\.")[1]).decode(), StandardCharsets.UTF_8);
    JsonNode undisclosed = mapper.readTree(jwtBody);
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    java.util.Set<String> digests = new java.util.HashSet<>();
    collectDigests(undisclosed, digests);
    assertThat(digests).isNotEmpty();
    int checked = 0;
    for (int i = 1; i < parts.length; i++) {
      if (parts[i].isEmpty()) {
        continue;
      }
      String disclosureJson = new String(
          Base64URL.from(parts[i]).decode(), StandardCharsets.UTF_8);
      JsonNode disclosure = mapper.readTree(disclosureJson);
      assertThat(disclosure.isArray()).isTrue();
      assertThat(disclosure.size()).isEqualTo(3);
      assertThat(disclosure.get(1).asString()).isEqualTo("adultOver18");
      assertThat(disclosure.get(2).asBoolean()).isTrue();
      String digest = Base64URL.encode(
          sha256.digest(parts[i].getBytes(StandardCharsets.US_ASCII))).toString();
      assertThat(digests).contains(digest);
      checked++;
    }
    assertThat(checked).isEqualTo(1);
  }

  private void collectDigests(JsonNode node, java.util.Set<String> digests) {
    if (node == null || !node.isObject()) {
      return;
    }
    JsonNode sd = node.get("_sd");
    if (sd != null && sd.isArray()) {
      sd.forEach(digest -> digests.add(digest.asString()));
    }
    node.properties().forEach(entry -> {
      if (entry.getValue().isObject()) {
        collectDigests(entry.getValue(), digests);
      }
    });
  }

  @Test
  void providerRefusesWrongKeyAndHeaders() throws Exception {
    Keys issuer = generateKeys();
    TestSigner signer = new TestSigner(new KeyRef(ISSUER, "synth-1", 1), issuer.privateKey());
    SovraIssuerCryptoProvider provider =
        new SovraIssuerCryptoProvider(signer, new KeyRef(ISSUER, "synth-1", 1), UUID.randomUUID());
    kotlinx.serialization.json.JsonObject payload =
        new kotlinx.serialization.json.JsonObject(Collections.<String, kotlinx.serialization.json.JsonElement>emptyMap());
    assertThatThrownBy(() -> provider.sign(payload, "other-key", "dc+sd-jwt",
            Collections.<String, Object>emptyMap()))
        .isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> provider.sign(payload, "synth-1", "dc+sd-jwt",
            Map.of("evil", (Object) "x")))
        .isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> provider.verify("a.b.c", "synth-1"))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThat(signer.calls).isZero();
  }

  @Test
  void encoderEnforcesAllowlistAndBinding() throws Exception {
    Keys issuer = generateKeys();
    Keys holder = generateHolderKeys();
    TestSigner signer = new TestSigner(new KeyRef(ISSUER, "synth-1", 1), issuer.privateKey());
    WaltIdSdJwtVcEncoder encoder = new WaltIdSdJwtVcEncoder(signer);
    IssuanceEvidence input = evidence(holder);

    IssuanceEvidence wrongType = new IssuanceEvidence(
        input.credentialId(), input.issuerId(), input.keyRef(),
        "https://sovra.example/vct/other/1", input.claims(), input.holderThumbprint(),
        input.issuedAt(), input.expiresAt(), input.trustSnapshotVersion(), input.statusUri(),
        input.holderJwk());
    assertThatThrownBy(() -> encoder.encode(wrongType))
        .isInstanceOf(InvalidIssuanceException.class);

    IssuanceEvidence noKey = new IssuanceEvidence(
        input.credentialId(), input.issuerId(), input.keyRef(), input.vct(),
        input.claims(), input.holderThumbprint(), input.issuedAt(), input.expiresAt(),
        input.trustSnapshotVersion(), input.statusUri(), null);
    assertThatThrownBy(() -> encoder.encode(noKey))
        .isInstanceOf(InvalidIssuanceException.class);
    assertThat(signer.calls).isZero();
  }

  @Test
  void waltNimbusPathWorksUnderResolved103() throws Exception {
    // walt-id compiled against Nimbus 10.10; our tree pins 10.3. Any
    // newer API usage fails here loudly instead of in production.
    Keys issuer = generateKeys();
    SimpleJWTCryptoProvider provider = new SimpleJWTCryptoProvider(
        JWSAlgorithm.ES256, new ECDSASigner(issuer.privateKey()),
        new ECDSAVerifier(issuer.publicKey()));
    kotlinx.serialization.json.JsonObject payload =
        new kotlinx.serialization.json.JsonObject(Map.of(
            "sub", kotlinx.serialization.json.JsonElementKt.JsonPrimitive("probe")));
    String jwt = provider.sign(payload, "synth-1", "JWT", Collections.<String, Object>emptyMap());
    assertThat(provider.verify(jwt, "synth-1").getVerified()).isTrue();
  }

  private Keys generateHolderKeys() throws Exception {
    return generateKeys();
  }
}
