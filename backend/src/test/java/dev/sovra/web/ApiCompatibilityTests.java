package dev.sovra.web;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sovra.SovraAppRoleBase;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.yaml.snakeyaml.Yaml;

/**
 * Provider/consumer parity gate (SOV-015, IF-09, SEC-42): every
 * controller route must be documented in the pinned OpenAPI contract,
 * and no documented path may be stale. A behavior change without a
 * contract bump fails here.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApiCompatibilityTests extends SovraAppRoleBase {

  /** Contract version this build implements; bump with any behavior change. */
  static final String EXPECTED_CONTRACT_VERSION = "0.2.0";

  @Autowired
  @org.springframework.beans.factory.annotation.Qualifier("requestMappingHandlerMapping")
  RequestMappingHandlerMapping mappings;

  @SuppressWarnings("unchecked")
  private Map<String, Object> contract() throws Exception {
    Path yaml = Path.of("../docs/engineering/implemented-api.openapi.yaml");
    assertThat(Files.isRegularFile(yaml)).isTrue();
    return new Yaml().load(Files.readString(yaml));
  }

  private static Set<String> routes(Map<RequestMappingInfo, ?> handlerMethods) {
    Set<String> routes = new TreeSet<>();
    for (RequestMappingInfo info : handlerMethods.keySet()) {
      Set<String> patterns = new TreeSet<>();
      if (info.getPathPatternsCondition() != null) {
        info.getPathPatternsCondition().getPatterns()
            .forEach(p -> patterns.add(p.getPatternString()));
      }
      if (patterns.isEmpty() && info.getPatternsCondition() != null) {
        patterns.addAll(info.getPatternsCondition().getPatterns());
      }
      Set<RequestMethod> methods = info.getMethodsCondition().getMethods();
      for (String pattern : patterns) {
        if (pattern.equals("/error")) {
          continue;
        }
        if (methods.isEmpty()) {
          routes.add("* " + pattern);
        } else {
          for (RequestMethod method : methods) {
            routes.add(method.name() + " " + pattern);
          }
        }
      }
    }
    return routes;
  }

  @Test
  @SuppressWarnings("unchecked")
  void everyRouteIsDocumentedAtThePinnedVersion() throws Exception {
    Map<String, Object> spec = contract();
    Map<String, Object> info = (Map<String, Object>) spec.get("info");
    assertThat(info.get("version")).isEqualTo(EXPECTED_CONTRACT_VERSION);

    Map<String, Object> paths = (Map<String, Object>) spec.get("paths");
    Set<String> documented = new TreeSet<>();
    for (Map.Entry<String, Object> path : paths.entrySet()) {
      Map<String, Object> operations = (Map<String, Object>) path.getValue();
      for (String method : operations.keySet()) {
        documented.add(method.toUpperCase() + " " + path.getKey());
      }
    }

    Set<String> implemented = routes(mappings.getHandlerMethods());
    assertThat(implemented).isNotEmpty();
    List<String> undocumented = new ArrayList<>(implemented);
    undocumented.removeAll(documented);
    assertThat(undocumented).as("routes missing from implemented-api.openapi.yaml").isEmpty();

    List<String> stale = new ArrayList<>(documented);
    stale.removeAll(implemented);
    assertThat(stale).as("documented paths with no controller route").isEmpty();
  }

  @Test
  @SuppressWarnings("unchecked")
  void everyOperationDeclaresItsScopes() throws Exception {
    Map<String, Object> spec = contract();
    Map<String, Object> paths = (Map<String, Object>) spec.get("paths");
    List<String> missing = new ArrayList<>();
    for (Map.Entry<String, Object> path : paths.entrySet()) {
      Map<String, Object> operations = (Map<String, Object>) path.getValue();
      for (Map.Entry<String, Object> operation : operations.entrySet()) {
        Map<String, Object> details = (Map<String, Object>) operation.getValue();
        if (!details.containsKey("x-sovra-scopes")) {
          missing.add(operation.getKey().toUpperCase() + " " + path.getKey());
        }
      }
    }
    assertThat(missing).as("operations without x-sovra-scopes").isEmpty();
  }
}
