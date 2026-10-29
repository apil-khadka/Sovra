package dev.sovra;

import dev.sovra.bff.BffProperties;
import dev.sovra.config.DemoProperties;
import dev.sovra.planning.PlanningProperties;
import org.springframework.ai.model.openai.autoconfigure.OpenAiAudioSpeechAutoConfiguration;
import org.springframework.ai.model.openai.autoconfigure.OpenAiAudioTranscriptionAutoConfiguration;
import org.springframework.ai.model.openai.autoconfigure.OpenAiChatAutoConfiguration;
import org.springframework.ai.model.openai.autoconfigure.OpenAiEmbeddingAutoConfiguration;
import org.springframework.ai.model.openai.autoconfigure.OpenAiImageAutoConfiguration;
import org.springframework.ai.model.openai.autoconfigure.OpenAiModerationAutoConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * SOV-013: Spring AI's OpenAI autoconfigurations stay excluded so the
 * service boots keyless by default. The live chat model is built by
 * hand from {@link PlanningProperties} (environment only) and only
 * when live planning is explicitly enabled.
 */
@SpringBootApplication(
    exclude = {
      OpenAiChatAutoConfiguration.class,
      OpenAiEmbeddingAutoConfiguration.class,
      OpenAiImageAutoConfiguration.class,
      OpenAiAudioSpeechAutoConfiguration.class,
      OpenAiAudioTranscriptionAutoConfiguration.class,
      OpenAiModerationAutoConfiguration.class
    })
@EnableConfigurationProperties({BffProperties.class, DemoProperties.class, PlanningProperties.class})
public class SovraApplication {

  public static void main(String[] args) {
    SpringApplication.run(SovraApplication.class, args);
  }
}
