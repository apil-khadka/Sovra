package dev.sovra.bff;

import dev.sovra.bff.BffLoginService.BffLoginDeniedException;
import dev.sovra.bff.BffLoginService.LoginResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

/**
 * Login landing: provisions membership, pins the session to the
 * membership id, holds tokens server-side, then returns to the
 * frontend root (the BFF does not cache API requests). Denials redirect with
 * the audit-safe reason; nothing secret-bearing ever lands in the
 * URL.
 */
public class BffLoginHandlers {

  private BffLoginHandlers() {}

  public static SavedRequestAwareAuthenticationSuccessHandler success(BffLoginService logins) {
    return new SavedRequestAwareAuthenticationSuccessHandler() {
      @Override
      public void onAuthenticationSuccess(
          HttpServletRequest request, HttpServletResponse response, Authentication authentication)
          throws IOException, jakarta.servlet.ServletException {
        OidcUser user = oidcUser(authentication);
        if (user == null) {
          response.sendRedirect("/?auth_error=UNTRUSTED_ISSUER");
          return;
        }
        try {
          LoginResult result = logins.login(user);
          HttpSession session = request.getSession(true);
          session.setAttribute(
              BffLoginService.SESSION_MEMBERSHIP, result.principal().id().toString());
          session.setAttribute(BffLoginService.SESSION_AMR, result.amr());
          session.setAttribute(BffLoginService.SESSION_AUTH_TIME, result.authTime().toString());
          session.setAttribute(BffLoginService.SESSION_ID_TOKEN, result.idToken());
          super.onAuthenticationSuccess(request, response, authentication);
        } catch (BffLoginDeniedException denied) {
          HttpSession existing = request.getSession(false);
          if (existing != null) {
            existing.invalidate();
          }
          response.sendRedirect("/?auth_error=" + denied.reasonCode().name());
        }
      }
    };
  }

  private static OidcUser oidcUser(Authentication authentication) {
    if (authentication instanceof OAuth2AuthenticationToken token
        && token.getPrincipal() instanceof OidcUser user) {
      return user;
    }
    return null;
  }
}
