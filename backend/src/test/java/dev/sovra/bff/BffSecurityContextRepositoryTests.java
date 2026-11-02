package dev.sovra.bff;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpRequestResponseHolder;

/**
 * Marker-only context storage (PROD-003): real authentications set
 * the marker, anonymous state clears it without creating sessions,
 * and a marked session loads a non-null placeholder so fixation
 * runs at login, never on later calls.
 */
class BffSecurityContextRepositoryTests {

  BffSecurityContextRepository repository = new BffSecurityContextRepository();

  @Test
  void realAuthenticationSetsTheMarker() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    SecurityContextImpl context = new SecurityContextImpl(
        new TestingAuthenticationToken("user", "secret", "ROLE_USER"));

    repository.saveContext(context, request, new MockHttpServletResponse());

    MockHttpSession session = (MockHttpSession) request.getSession(false);
    assertThat(session).isNotNull();
    assertThat(session.getAttribute(BffSecurityContextRepository.MARKER_ATTR)).isEqualTo("1");
    assertThat(repository.containsContext(request)).isTrue();
  }

  @Test
  void markedSessionsLoadANonNullPlaceholder() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.getSession(true).setAttribute(BffSecurityContextRepository.MARKER_ATTR, "1");

    SecurityContextImpl loaded = (SecurityContextImpl) repository.loadContext(
        new HttpRequestResponseHolder(request, new MockHttpServletResponse()));

    assertThat(loaded.getAuthentication()).isNotNull();
    // The placeholder grants nothing and names itself honestly.
    assertThat(loaded.getAuthentication().getAuthorities()).hasSize(1);
    assertThat(loaded.getAuthentication().getAuthorities().iterator().next().getAuthority())
        .isEqualTo("SOVRA_SESSION_MARKER");
  }

  @Test
  void unmarkedSessionsLoadAnEmptyContext() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    assertThat(repository.loadContext(new HttpRequestResponseHolder(request, new MockHttpServletResponse()))
        .getAuthentication())
        .isNull();
    request.getSession(true);
    assertThat(repository.loadContext(new HttpRequestResponseHolder(request, new MockHttpServletResponse()))
        .getAuthentication())
        .isNull();
    assertThat(repository.containsContext(request)).isFalse();
  }

  @Test
  void anonymousSaveClearsWithoutCreatingSessions() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.getSession(true).setAttribute(BffSecurityContextRepository.MARKER_ATTR, "1");

    repository.saveContext(new SecurityContextImpl(), request, new MockHttpServletResponse());
    assertThat(
            ((MockHttpSession) request.getSession(false))
                .getAttribute(BffSecurityContextRepository.MARKER_ATTR))
        .isNull();

    MockHttpServletRequest bare = new MockHttpServletRequest();
    repository.saveContext(new SecurityContextImpl(), bare, new MockHttpServletResponse());
    assertThat(bare.getSession(false)).isNull();
  }

  @Test
  void placeholderItselfNeverSetsTheMarker() {
    // Saving the placeholder back (belt and braces: no caller should
    // ever do this) must not re-arm a session.
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.getSession(true).setAttribute(BffSecurityContextRepository.MARKER_ATTR, "1");
    SecurityContextImpl placeholder = (SecurityContextImpl) repository.loadContext(
        new HttpRequestResponseHolder(request, new MockHttpServletResponse()));

    MockHttpServletRequest fresh = new MockHttpServletRequest();
    repository.saveContext(placeholder, fresh, new MockHttpServletResponse());

    assertThat(fresh.getSession(false)).isNull();
  }
}
