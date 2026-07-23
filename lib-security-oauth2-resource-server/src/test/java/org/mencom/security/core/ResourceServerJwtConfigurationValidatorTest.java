package org.mencom.security.core;

import org.junit.jupiter.api.Test;
import org.mencom.common.diagnostics.InvalidException;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.mock.env.MockEnvironment;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.assertj.core.api.Assertions.assertThat;

class ResourceServerJwtConfigurationValidatorTest {

    @Test
    void allowsCustomEntriesWhenDefaultSpringResourceServerIsNotConfigured() {
        MockEnvironment environment = new MockEnvironment();
        GenericApplicationContext applicationContext = new GenericApplicationContext();
        applicationContext.setEnvironment(environment);

        assertDoesNotThrow(() -> new ResourceServerJwtConfigurationValidator()
                .initialize(applicationContext));
    }

    @Test
    void failsWhenDefaultIssuerUriIsConfigured() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.security.oauth2.resourceserver.jwt.issuer-uri", "https://issuer.example");

        InvalidException exception = assertThrows(InvalidException.class, () -> validate(environment));

        assertThat(exception.getMessage()).contains("spring.security.oauth2.resourceserver.jwt.issuer-uri");
    }

    @Test
    void failsWhenDefaultJwkSetUriIsConfigured() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.security.oauth2.resourceserver.jwt.jwk-set-uri", "https://issuer.example/.well-known/jwks.json");

        InvalidException exception = assertThrows(InvalidException.class, () -> validate(environment));

        assertThat(exception.getMessage()).contains("spring.security.oauth2.resourceserver.jwt.jwk-set-uri");
    }

    private static void validate(MockEnvironment environment) {
        GenericApplicationContext applicationContext = new GenericApplicationContext();
        applicationContext.setEnvironment(environment);
        new ResourceServerJwtConfigurationValidator().initialize(applicationContext);
    }
}



