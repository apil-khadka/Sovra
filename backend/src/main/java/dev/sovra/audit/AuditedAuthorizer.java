package dev.sovra.audit;

import dev.sovra.auth.ServiceAccountPrincipal;
import dev.sovra.authz.Action;
import dev.sovra.authz.AuthorizationService;
import dev.sovra.authz.Decision;
import dev.sovra.authz.ForbiddenException;
import dev.sovra.authz.ReasonCode;
import dev.sovra.authz.ResourceRef;
import dev.sovra.authz.TenantMismatchException;
import java.util.Optional;

/**
 * Authorization with mandatory denial evidence. Every refusal lands
 * an audit row before the exception leaves, so silent denials are
 * unrepresentable at call sites that use this entry. Anonymous
 * callers stay unaudited (nothing to attribute them to); controllers
 * reject those before calling here, as today.
 */
public final class AuditedAuthorizer {

  private AuditedAuthorizer() {}

  /**
   * Authorizes the action, recording any denial. Cross-tenant access
   * throws {@link TenantMismatchException} (rendered 404, empty);
   * other denials throw {@link ForbiddenException}.
   */
  public static Decision require(
      AuthorizationService authz,
      AuditService audit,
      ServiceAccountPrincipal caller,
      Action action,
      ResourceRef resource) {
    Decision decision = authz.authorize(Optional.of(caller), action, resource);
    if (decision.permitted()) {
      return decision;
    }
    audit.recordDenial(caller, action, resource, decision.reasonCode(), decision.policyVersion());
    if (decision.reasonCode() == ReasonCode.WRONG_TENANT) {
      throw new TenantMismatchException();
    }
    throw new ForbiddenException(decision.reasonCode());
  }
}
