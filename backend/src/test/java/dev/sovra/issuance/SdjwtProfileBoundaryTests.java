package dev.sovra.issuance;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sovra.guard.ApprovedSchemas;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * SD-JWT VC profile boundary: the encoder stays legacy adult-status-only
 * and refuses mapped registry types without touching the signer. New
 * schemas are synthetic-profile-only; this refusal is the explicit seam.
 */
class SdjwtProfileBoundaryTests {

  @Test
  void sdjwtEncoderRefusesMappedTypesBeforeSigning() {
    IssuerSigner refuse = (ref, payload, aad) -> {
      throw new AssertionError("signer must not be called for refused types");
    };
    WaltIdSdJwtVcEncoder encoder = new WaltIdSdJwtVcEncoder(refuse);
    IssuanceEvidence fjord = new IssuanceEvidence(
        UUID.randomUUID(), LocalDevSigner.SECOND_ISSUER_ID,
        new KeyRef(LocalDevSigner.SECOND_ISSUER_ID, "synth-2", 1),
        ApprovedSchemas.FJORD_VCT, Map.of("isAdult", Boolean.TRUE), "thumb",
        Instant.now(), Instant.now().plusSeconds(60), 1, "/status", null);
    assertThatThrownBy(() -> encoder.encode(fjord))
        .isInstanceOf(InvalidIssuanceException.class)
        .hasMessageContaining("synthetic-profile-only");
  }
}
