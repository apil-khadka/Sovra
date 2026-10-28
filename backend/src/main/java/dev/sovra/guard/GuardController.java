package dev.sovra.guard;

import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.web.CurrentPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;

/**
 * Plan-guard endpoint. Adjudicates one untrusted candidate plan against
 * live trust state and the RP-selected policy binding, before any
 * holder request is created. Rejections return 200 with an explicit
 * non-accepted verdict; only a malformed envelope is a 400.
 */
@RestController
@RequestMapping("/api/guard")
public class GuardController {

  private final GuardService guard;

  public GuardController(GuardService guard) {
    this.guard = guard;
  }

  @PostMapping("/validate")
  public ResponseEntity<GuardService.VerdictView> validate(
      @Valid @RequestBody ValidateRequest request) {
    var caller =
        CurrentPrincipal.get().orElseThrow(() -> new ForbiddenException(ReasonCode.ANONYMOUS));
    CandidatePlan plan = PlanParser.parsePlan(request.plan());
    SelectedPolicy selected = PlanParser.parseSelected(request.policyId(), request.policyVersion());
    return ResponseEntity.ok(guard.adjudicate(caller, plan, selected));
  }

  public record ValidateRequest(
      @NotNull JsonNode plan, @NotNull String policyId, @NotNull String policyVersion) {}
}
