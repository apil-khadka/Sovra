package dev.sovra.consent;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Claim scalars keep their JSON shape; large integrals stay exact. */
class ConsentScalarTests {

  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void integralNumbersStayLong() throws Exception {
    JsonNode node = mapper.readTree("{\"big\": 9007199254740993, \"small\": 18}");
    assertThat(ConsentService.scalar(node.get("big"))).isEqualTo(9007199254740993L);
    assertThat(ConsentService.scalar(node.get("small"))).isEqualTo(18L);
  }

  @Test
  void decimalsBooleansAndStringsKeepShape() throws Exception {
    JsonNode node = mapper.readTree("{\"ratio\": 1.5, \"flag\": true, \"name\": \"ada\"}");
    assertThat(ConsentService.scalar(node.get("ratio"))).isEqualTo(1.5);
    assertThat(ConsentService.scalar(node.get("flag"))).isEqualTo(Boolean.TRUE);
    assertThat(ConsentService.scalar(node.get("name"))).isEqualTo("ada");
  }
}
