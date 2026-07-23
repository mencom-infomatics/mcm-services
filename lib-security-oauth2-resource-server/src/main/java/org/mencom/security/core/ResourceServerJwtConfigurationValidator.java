package org.mencom.security.core;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.NonNull;
import org.mencom.common.diagnostics.InvalidException;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class ResourceServerJwtConfigurationValidator implements ApplicationContextInitializer<ConfigurableApplicationContext>, Ordered {

    private static final String STANDARD_ISSUER_URI = "spring.security.oauth2.resourceserver.jwt.issuer-uri";
    private static final String STANDARD_JWK_SET_URI = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri";

    @Override
    public void initialize(@NonNull ConfigurableApplicationContext applicationContext) {
        validateDefaultSpringResourceServerConfiguration(applicationContext.getEnvironment());
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }

    void validateDefaultSpringResourceServerConfiguration(@NonNull Environment environment) {
        List<String> unsupportedSettings = new ArrayList<>();
        if (StringUtils.isNotBlank(environment.getProperty(STANDARD_ISSUER_URI))) {
            unsupportedSettings.add(STANDARD_ISSUER_URI);
        }
        if (StringUtils.isNotBlank(environment.getProperty(STANDARD_JWK_SET_URI))) {
            unsupportedSettings.add(STANDARD_JWK_SET_URI);
        }

        if (!unsupportedSettings.isEmpty()) {
            String message = "Unsupported default Spring Security OAuth2 resource server configuration detected: "
                    + String.join(", ", unsupportedSettings)
                    + ". When using lib-security-oauth2-resource-server, remove the default Spring Security JWT configuration and use spring.security.oauth2.resourceserver.jwt.entries instead.";
            log.error(message);
            throw new InvalidException(
                    message,
                    "Remove the default Spring Security properties and use spring.security.oauth2.resourceserver.jwt.entries instead for this library.",
                    unsupportedSettings);
        }

        log.info("Validated Spring Security OAuth2 resource server properties before regular bean creation");
        log.trace("Default Spring Security JWT configuration is not present");
    }
}


