package dev.sovra.bff;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

/**
 * Shared BFF sessions over PostgreSQL (PROD-003). Any replica serves
 * any logged-in browser; restart and rolling upgrades keep sessions
 * alive instead of logging everyone out.
 *
 * <p>Boot 4 carries no session auto-configuration, so this class
 * enables the JDBC store explicitly. Three deliberate contracts: the
 * 30-minute timeout from {@code server.servlet.session.timeout} is
 * pinned here in seconds, the session cookie repeats the pre-sharing
 * posture exactly (JSESSIONID, Secure, HttpOnly, SameSite=Lax), and
 * attribute bytes are explicit JSON envelopes
 * ({@link SessionAttributeCodec}) — Java serialization never touches
 * the session store.
 */
@Configuration
@EnableJdbcHttpSession(maxInactiveIntervalInSeconds = 1800)
public class SessionSharingConfig {

  @Bean
  SessionAttributeCodec sessionAttributeCodec() {
    return new SessionAttributeCodec();
  }

  @Bean
  CookieSerializer cookieSerializer() {
    DefaultCookieSerializer serializer = new DefaultCookieSerializer();
    serializer.setCookieName("JSESSIONID");
    serializer.setUseSecureCookie(true);
    serializer.setSameSite("Lax");
    // Session ids are UUIDs, already cookie-safe: keep the cookie
    // human-readable (and greppable in tests) instead of base64.
    serializer.setUseBase64Encoding(false);
    return serializer;
  }

  @Bean
  SessionRepositoryCustomizer<JdbcIndexedSessionRepository> sessionRepositoryCustomizer(
      SessionAttributeCodec codec) {
    return repository -> {
      GenericConversionService conversions = new GenericConversionService();
      conversions.addConverter(Object.class, byte[].class, codec::encode);
      conversions.addConverter(byte[].class, Object.class, codec::decode);
      repository.setConversionService(conversions);
    };
  }
}
