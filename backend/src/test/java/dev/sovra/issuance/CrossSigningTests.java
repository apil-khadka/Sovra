package dev.sovra.issuance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.SovraAppRoleBase;
import dev.sovra.trust.TrustService;
import dev.sovra.trust.TrustSnapshotProvider;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.ObjectMapper;

/**
 * Per-node synthetic issuer isolation: a node configured for synth-1 holds
 * only scalar 1 and refuses synth-2 keys, and vice versa — even when the
 * active trust snapshot authorizes both. Unknown local-issuer values fail
 * fast at construction.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CrossSigningTests extends SovraAppRoleBase {

  @Autowired TrustService trust;

  @Autowired TrustSnapshotProvider snapshots;

  @Autowired ObjectMapper mapper;

  JdbcTemplate owner;

  @BeforeEach
  void setup() throws Exception {
    owner = new JdbcTemplate(ownerDataSource());
    DualIssuerFixtures.ensureDualIssuers(owner, trust, mapper);
  }

  private LocalDevSigner node(String localIssuer) throws Exception {
    return new LocalDevSigner(
        ownerDataSource(), snapshots, mapper, Clock.systemUTC(), true, true, localIssuer);
  }

  private static String aad(String issuer, KeyRef ref) {
    return AadContext.issuance(issuer, ref.encode(), "test-credential", "test-profile").encode();
  }

  @Test
  void synth1NodeRefusesSynth2Keys() throws Exception {
    LocalDevSigner node = node("synth-1");
    KeyRef foreign = new KeyRef(LocalDevSigner.SECOND_ISSUER_ID, "synth-2", 1);
    assertThatThrownBy(() -> node.sign(
            foreign, "payload".getBytes(StandardCharsets.UTF_8),
            aad(LocalDevSigner.SECOND_ISSUER_ID, foreign)))
        .isInstanceOf(SigningRefusedException.class);
  }

  @Test
  void synth2NodeRefusesSynth1Keys() throws Exception {
    LocalDevSigner node = node("synth-2");
    KeyRef foreign = new KeyRef(LocalDevSigner.ISSUER_ID, "synth-1", 1);
    assertThatThrownBy(() -> node.sign(
            foreign, "payload".getBytes(StandardCharsets.UTF_8),
            aad(LocalDevSigner.ISSUER_ID, foreign)))
        .isInstanceOf(SigningRefusedException.class);
  }

  @Test
  void eachNodeServesItsOwnIssuer() throws Exception {
    LocalDevSigner one = node("synth-1");
    KeyRef first = new KeyRef(LocalDevSigner.ISSUER_ID, "synth-1", 1);
    byte[] signature = one.sign(
        first, "payload".getBytes(StandardCharsets.UTF_8), aad(LocalDevSigner.ISSUER_ID, first));
    assertThat(signature).hasSize(64);

    LocalDevSigner two = node("synth-2");
    KeyRef second = new KeyRef(LocalDevSigner.SECOND_ISSUER_ID, "synth-2", 1);
    byte[] signature2 = two.sign(
        second, "payload".getBytes(StandardCharsets.UTF_8),
        aad(LocalDevSigner.SECOND_ISSUER_ID, second));
    assertThat(signature2).hasSize(64);
  }

  @Test
  void registeredPublicKeysDiffer() throws Exception {
    node("synth-1");
    node("synth-2");
    String first = owner.queryForObject(
        "SELECT public_key_jwk::text FROM issuer_signing_key"
            + " WHERE issuer_id = ? AND key_id = 'synth-1' AND key_version = 1",
        String.class, LocalDevSigner.ISSUER_ID);
    String second = owner.queryForObject(
        "SELECT public_key_jwk::text FROM issuer_signing_key"
            + " WHERE issuer_id = ? AND key_id = 'synth-2' AND key_version = 1",
        String.class, LocalDevSigner.SECOND_ISSUER_ID);
    assertThat(first).isNotEqualTo(second);
    var firstJwk = mapper.readTree(first);
    var secondJwk = mapper.readTree(second);
    assertThat(secondJwk.get("kid").asString()).isEqualTo("synth-2");
    // Distinct cryptographic keys, not just distinct labels: the P-256
    // coordinates themselves (generator vs 3G) must differ.
    assertThat(secondJwk.get("x").asString())
        .isNotEqualTo(firstJwk.get("x").asString());
    assertThat(secondJwk.get("y").asString())
        .isNotEqualTo(firstJwk.get("y").asString());
  }

  @Test
  void unknownLocalIssuerFailsFast() {
    assertThatThrownBy(() -> node("synth-9"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("local-issuer");
  }
}
