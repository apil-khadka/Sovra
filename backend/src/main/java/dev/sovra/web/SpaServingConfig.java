package dev.sovra.web;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;

/**
 * Packaged SPA delivery (SOV-041): serves the React production
 * bundle from the backend origin, so the SPA, BFF cookies,
 * authorization callback, and logout share one origin with the
 * API. The container build copies {@code frontend/dist} into
 * {@code classpath:/static}; a local run without a bundle (or
 * without a {@code spring.web.resources.static-locations} override
 * pointing at one) simply 404s these paths while the API is
 * unaffected.
 *
 * <p>Controllers keep precedence — resource handlers run last — so
 * {@code /api}, {@code /oauth2}, {@code /login}, and {@code /error}
 * can never be shadowed; the resolver additionally refuses every
 * reserved prefix (see {@link SpaRoutes}). Hashed Vite assets are
 * immutable for a year; entry HTML and history routes revalidate
 * every load.
 */
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class SpaServingConfig implements WebMvcConfigurer {

  private final WebProperties webProperties;

  public SpaServingConfig(WebProperties webProperties) {
    this.webProperties = webProperties;
  }

  @Override
  public void addResourceHandlers(ResourceHandlerRegistry registry) {
    String[] locations = webProperties.getResources().getStaticLocations();
    registry
        .addResourceHandler("/assets/**")
        .addResourceLocations(assetLocations(locations))
        .setCacheControl(CacheControl.maxAge(Duration.ofDays(365)).immutable());
    registry
        .addResourceHandler("/**")
        .addResourceLocations(locations)
        .setCacheControl(CacheControl.noStore())
        .resourceChain(true)
        .addResolver(new IndexFallbackResolver());
  }

  /**
   * The {@code /assets/**} mapping strips its prefix before
   * resolving, so its locations point one level deeper than the
   * entry handler's.
   */
  private static String[] assetLocations(String[] locations) {
    return Arrays.stream(locations)
        .map(location -> location.endsWith("/") ? location + "assets/" : location + "/assets/")
        .toArray(String[]::new);
  }

  /** Exact file when present, {@code index.html} for SPA routes, else 404. */
  static class IndexFallbackResolver extends PathResourceResolver {
    @Override
    protected Resource getResource(String resourcePath, Resource location) throws IOException {
      if (!resourcePath.isEmpty() && !resourcePath.endsWith("/")) {
        Resource exact = location.createRelative(resourcePath);
        if (exact.exists() && exact.isReadable()) {
          return exact;
        }
      }
      if (SpaRoutes.isHistoryFallback(resourcePath)) {
        Resource index = location.createRelative("index.html");
        if (index.exists() && index.isReadable()) {
          return index;
        }
      }
      return null;
    }
  }
}
