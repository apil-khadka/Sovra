package dev.sovra.planning;

import dev.sovra.auth.CurrentPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Planning endpoints (SOV-013). Proposals are untrusted candidates:
 * only the deterministic guard may accept a plan, and only the
 * holder's signed decision plus verification may act on one. The
 * fixture/live provenance travels in every response.
 */
@RestController
@RequestMapping("/api/plans")
public class PlanningController {

  private final PlanningService planning;

  public PlanningController(PlanningService planning) {
    this.planning = planning;
  }

  @PostMapping("/propose")
  public ResponseEntity<PlanningService.ProposalView> propose(
      @Valid @RequestBody ProposeRequest request) {
    var caller =
        CurrentPrincipal.require();
    PlanningIntent intent =
        PlanningIntents.validate(
            request.rpId(), request.audience(), request.purpose(), request.outcome(),
            request.policyId(), request.policyVersion(), request.requestedClaims());
    return ResponseEntity.ok(planning.propose(caller, intent));
  }

  @GetMapping("/status")
  public ResponseEntity<PlanningService.StatusView> status() {
    var caller =
        CurrentPrincipal.require();
    return ResponseEntity.ok(planning.status(caller));
  }

  public record ProposeRequest(
      @NotNull String rpId,
      @NotNull String audience,
      @NotNull String purpose,
      @NotNull String outcome,
      @NotNull String policyId,
      @NotNull String policyVersion,
      @NotNull List<String> requestedClaims) {}
}
