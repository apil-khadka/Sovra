package dev.sovra.openid;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

/** SOV-036 DCQL query/match unit coverage for the G1 single-credential profile. */
class DcqlTests {

  private final ObjectMapper mapper = new ObjectMapper();
  private static final String VCT = "https://sovra.example/vct/adult-status/1";

  @Test
  void queryNamesFormatVctAndClaim() throws Exception {
    var query = Dcql.queryFor(VCT);
    var node = mapper.readTree(mapper.writeValueAsString(query));
    assertThat(node.get("credentials").size()).isEqualTo(1);
    var credential = node.get("credentials").get(0);
    assertThat(credential.get("id").asString()).isEqualTo("sovra-adult-status");
    assertThat(credential.get("format").asString()).isEqualTo("dc+sd-jwt");
    assertThat(credential.get("meta").get("vct_values").get(0).asString()).isEqualTo(VCT);
    var claim = credential.get("claims").get(0);
    assertThat(claim.get("id").asString()).isEqualTo("adult-flag");
    assertThat(claim.get("path").get(0).asString()).isEqualTo("claims");
    assertThat(claim.get("values").get(0).asBoolean()).isTrue();
  }

  @Test
  void fulfilledPresentationMatches() throws Exception {
    var query = mapper.readTree(mapper.writeValueAsString(Dcql.queryFor(VCT)));
    var disclosed = mapper.readTree("{\"adultOver18\":true}");
    assertThat(Dcql.match(query, "dc+sd-jwt", VCT, disclosed)).isEmpty();
  }

  @Test
  void wrongVctMismatches() throws Exception {
    var query = mapper.readTree(mapper.writeValueAsString(Dcql.queryFor(VCT)));
    var disclosed = mapper.readTree("{\"adultOver18\":true}");
    assertThat(Dcql.match(query, "dc+sd-jwt", "https://sovra.example/vct/other/1", disclosed))
        .contains("VCT_MISMATCH");
  }

  @Test
  void wrongFormatMismatches() throws Exception {
    var query = mapper.readTree(mapper.writeValueAsString(Dcql.queryFor(VCT)));
    var disclosed = mapper.readTree("{\"adultOver18\":true}");
    assertThat(Dcql.match(query, "jwt_vc_json-ld", VCT, disclosed)).contains("FORMAT_MISMATCH");
  }

  @Test
  void undisclosedClaimMismatches() throws Exception {
    var query = mapper.readTree(mapper.writeValueAsString(Dcql.queryFor(VCT)));
    var disclosed = mapper.readTree("{}");
    assertThat(Dcql.match(query, "dc+sd-jwt", VCT, disclosed)).contains("CLAIMS_MISMATCH");
  }

  @Test
  void wrongClaimValueMismatches() throws Exception {
    var query = mapper.readTree(mapper.writeValueAsString(Dcql.queryFor(VCT)));
    var disclosed = mapper.readTree("{\"adultOver18\":false}");
    assertThat(Dcql.match(query, "dc+sd-jwt", VCT, disclosed)).contains("CLAIMS_MISMATCH");
  }

  @Test
  void multiCredentialQueryUnsupported() throws Exception {
    var query =
        mapper.readTree(
            "{\"credentials\":[{\"id\":\"a\"},{\"id\":\"b\"}]}");
    var disclosed = mapper.readTree("{\"adultOver18\":true}");
    assertThat(Dcql.match(query, "dc+sd-jwt", VCT, disclosed))
        .contains("DCQL_SHAPE_UNSUPPORTED");
  }

  @Test
  void missingQueryRejected() throws Exception {
    var disclosed = mapper.readTree("{\"adultOver18\":true}");
    assertThat(Dcql.match(null, "dc+sd-jwt", VCT, disclosed)).contains("DCQL_QUERY_MISSING");
    assertThat(Dcql.match(mapper.readTree("{}"), "dc+sd-jwt", VCT, disclosed))
        .contains("DCQL_SHAPE_UNSUPPORTED");
  }

  @Test
  void submissionMapsTheG1Claim() throws Exception {
    var node = mapper.readTree(mapper.writeValueAsString(Dcql.submission()));
    var descriptor = node.get("descriptor_map").get(0);
    assertThat(descriptor.get("id").asString()).isEqualTo("adult-flag");
    assertThat(descriptor.get("format").asString()).isEqualTo("dc+sd-jwt");
  }

  @Test
  void oversizedQueryRejected() {
    assertThat(
            org.assertj.core.api.Assertions.catchThrowable(
                () -> Dcql.parseQuery("x".repeat(100), mapper, 10)))
        .isInstanceOf(InvalidOpenIdRequestException.class);
  }

  @Test
  void queryMapRoundTrips() {
    assertThat(Dcql.queryFor(VCT)).isInstanceOf(Map.class);
  }
}
