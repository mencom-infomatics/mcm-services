package org.mencom.security.core;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ResourceServerJwtConditionTest {

    private final ResourceServerJwtCondition condition = new ResourceServerJwtCondition();

    @Test
    void matchesWhenCustomEntriesAreConfigured() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.security.oauth2.resourceserver.jwt.entries[0].issuer-uri", "https://issuer.example");

        ConditionOutcome outcome = evaluate(environment);

        assertThat(outcome.isMatch()).isTrue();
    }

    @Test
    void matchesWhenStandardIssuerUriIsConfigured() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.security.oauth2.resourceserver.jwt.issuer-uri", "https://issuer.example");

        ConditionOutcome outcome = evaluate(environment);

        assertThat(outcome.isMatch()).isTrue();
    }

    @Test
    void doesNotMatchWhenNoJwtPropertiesExist() {
        MockEnvironment environment = new MockEnvironment();

        ConditionOutcome outcome = evaluate(environment);

        assertThat(outcome.isMatch()).isFalse();
    }

    private ConditionOutcome evaluate(MockEnvironment environment) {
        ConditionContext context = mock(ConditionContext.class);
        AnnotatedTypeMetadata metadata = mock(AnnotatedTypeMetadata.class);
        when(context.getEnvironment()).thenReturn(environment);
        return condition.getMatchOutcome(context, metadata);
    }
}

