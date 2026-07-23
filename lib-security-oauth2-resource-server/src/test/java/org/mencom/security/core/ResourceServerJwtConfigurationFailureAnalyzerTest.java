package org.mencom.security.core;

import org.junit.jupiter.api.Test;
import org.mencom.common.diagnostics.InvalidException;
import org.mencom.common.diagnostics.MCMFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;

class ResourceServerJwtConfigurationFailureAnalyzerTest {

    @Test
    void createsHelpfulFailureAnalysisForUnsupportedSpringSecuritySettings() {
        InvalidException exception = new InvalidException(
                "lib-security-oauth2-resource-server cannot start because default Spring Security OAuth2 resource server properties are configured: spring.security.oauth2.resourceserver.jwt.issuer-uri, spring.security.oauth2.resourceserver.jwt.jwk-set-uri.",
                "Remove the default Spring Security properties and use spring.security.oauth2.resourceserver.jwt.entries instead for this library.",
                java.util.List.of("spring.security.oauth2.resourceserver.jwt.issuer-uri",
                        "spring.security.oauth2.resourceserver.jwt.jwk-set-uri"));

        FailureAnalysis analysis = (FailureAnalysis) ReflectionTestUtils.invokeMethod(
                new MCMFailureAnalyzer(),
                "analyze",
                exception,
                exception);

        Objects.requireNonNull(analysis);

        assertThat((String) ReflectionTestUtils.getField(analysis, "description"))
                .contains("cannot start")
                .contains("issuer-uri")
                .contains("jwk-set-uri");
        assertThat((String) ReflectionTestUtils.getField(analysis, "action"))
                .contains("spring.security.oauth2.resourceserver.jwt.entries");
    }
}





