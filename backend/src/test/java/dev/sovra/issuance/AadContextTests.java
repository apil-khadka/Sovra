package dev.sovra.issuance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * Signer call-context framing: construction rejects values that
 * would break the {@code k=v;k=v} wire form, and parsing refuses
 * duplicate keys instead of last-wins, so a crafted value can
 * never inject or override fields.
 */
class AadContextTests {

  @Test
  void roundTripPreservesFields() {
    AadContext context =
        AadContext.issuance("issuer-1", "key-1", "credential-1", "schema-1");
    AadContext.Parsed parsed = AadContext.parse(context.encode());
    assertThat(new AadContext(parsed.issuer(), parsed.key(), parsed.credential(),
        parsed.purpose(), parsed.schema())).isEqualTo(context);
  }

  @Test
  void framingBreakersAreUnconstructable() {
    assertThatThrownBy(() -> new AadContext("a;b", "k", "c", "issuance", "s"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new AadContext("a", "k", null, "issuance", "s"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> AadContext.issuance("a;b", "k", "c", "s"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> AadContext.issuance("a=b", "k", "c", "s"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> AadContext.issuance(" ", "k", "c", "s"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void duplicateKeysRefuseInsteadOfLastWins() {
    // A second issuer= naming us must not override the first.
    String forged = "issuer=evil;key=k;credential=c;purpose=issuance;schema=s;issuer=us";
    assertThatThrownBy(() -> AadContext.parse(forged))
        .isInstanceOf(SigningRefusedException.class)
        .hasMessageContaining("repeats a field");
  }

  @Test
  void malformedSegmentsVoidTheCall() {
    assertThatThrownBy(() -> AadContext.parse("issuer=a;BOGUS"))
        .isInstanceOf(SigningRefusedException.class);
    assertThatThrownBy(() -> AadContext.parse(" "))
        .isInstanceOf(SigningRefusedException.class);
  }

  @Test
  void unknownKeysAreToleratedButMissingFieldsStayNull() {
    AadContext.Parsed context = AadContext.parse("issuer=a;note=x;purpose=issuance");
    assertThat(context.issuer()).isEqualTo("a");
    assertThat(context.key()).isNull();
    assertThat(context.purpose()).isEqualTo("issuance");
  }
}
