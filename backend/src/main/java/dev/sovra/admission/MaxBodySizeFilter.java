package dev.sovra.admission;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Ingress byte budgets (PROD-006). Runs before authentication: a
 * declared {@code Content-Length} past the budget is rejected
 * without reading a byte, and streamed or chunked bodies are cut
 * off mid-read — before base64 decoders, JSON parsers, or domain
 * code can allocate for them. Document paths carry a larger budget
 * for legitimate vault/quarantine payloads. Second only to the
 * correlation filter, which reads one header and touches no body.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class MaxBodySizeFilter extends OncePerRequestFilter {

  private final AdmissionProperties properties;

  public MaxBodySizeFilter(AdmissionProperties properties) {
    this.properties = properties;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    if (!hasBody(request)) {
      chain.doFilter(request, response);
      return;
    }
    long limit = limitFor(request.getServletPath());
    long declared = request.getContentLengthLong();
    if (declared > limit) {
      writeTooLarge(request, response);
      return;
    }
    chain.doFilter(new BoundedRequest(request, limit), response);
  }

  private static boolean hasBody(HttpServletRequest request) {
    String method = request.getMethod();
    return "POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method);
  }

  private long limitFor(String path) {
    if (path.startsWith("/api/vault/")
        || path.startsWith("/api/quarantine/")
        || path.startsWith("/api/extraction/")
        || path.startsWith("/api/enrollments/")) {
      return properties.bodies().documentMaxBytes();
    }
    return properties.bodies().defaultMaxBytes();
  }

  private void writeTooLarge(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    response.setStatus(413);
    String accept = request.getHeader("Accept");
    if (accept != null && accept.contains("application/problem+json")) {
      response.setContentType("application/problem+json");
      response.getWriter()
          .write(
              "{\"type\":\"about:blank\",\"title\":\"body_too_large\",\"status\":413,"
                  + "\"code\":\"body_too_large\",\"correlationId\":\""
                  + dev.sovra.web.CorrelationIds.currentOrRandom()
                  + "\",\"retryable\":false}");
    } else {
      response.setContentType("application/json;charset=UTF-8");
      response.getWriter().write("{\"error\":\"body_too_large\"}");
    }
  }

  /** Request wrapper whose stream and reader stop past the budget. */
  static final class BoundedRequest extends HttpServletRequestWrapper {

    private final long limit;

    BoundedRequest(HttpServletRequest request, long limit) {
      super(request);
      this.limit = limit;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
      return new BoundedStream(super.getInputStream(), limit);
    }

    @Override
    public BufferedReader getReader() throws IOException {
      return new BufferedReader(
          new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }
  }

  static final class BoundedStream extends ServletInputStream {

    private final ServletInputStream delegate;
    private final long limit;
    private long read;

    BoundedStream(ServletInputStream delegate, long limit) {
      this.delegate = delegate;
      this.limit = limit;
    }

    @Override
    public int read() throws IOException {
      int next = delegate.read();
      if (next != -1) {
        count(1);
      }
      return next;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      int n = delegate.read(b, off, len);
      if (n > 0) {
        count(n);
      }
      return n;
    }

    private void count(long n) {
      read += n;
      if (read > limit) {
        throw new BodyTooLargeException();
      }
    }

    @Override
    public boolean isFinished() {
      return delegate.isFinished();
    }

    @Override
    public boolean isReady() {
      return delegate.isReady();
    }

    @Override
    public void setReadListener(ReadListener listener) {
      delegate.setReadListener(listener);
    }
  }
}
