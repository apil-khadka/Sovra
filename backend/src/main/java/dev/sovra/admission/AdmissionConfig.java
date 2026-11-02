package dev.sovra.admission;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Binds {@code sovra.admission.*} budgets (PROD-006). */
@Configuration
@EnableConfigurationProperties(AdmissionProperties.class)
public class AdmissionConfig {}
