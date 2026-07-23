package org.mencom.security.core;

import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.type.AnnotatedTypeMetadata;

@Slf4j
public class ResourceServerJwtCondition extends SpringBootCondition {

    private static final String CUSTOM_ENTRIES_PREFIX = "spring.security.oauth2.resourceserver.jwt.entries";
    private static final String STANDARD_ISSUER_URI = "spring.security.oauth2.resourceserver.jwt.issuer-uri";
    private static final String STANDARD_JWK_SET_URI = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri";

    @NonNull
    @Override
    public ConditionOutcome getMatchOutcome(@NonNull ConditionContext context, @NonNull AnnotatedTypeMetadata metadata) {
        boolean customEntriesConfigured = hasPrefixedProperty(context.getEnvironment(), CUSTOM_ENTRIES_PREFIX);
        boolean standardJwtConfigured = hasPrefixedProperty(context.getEnvironment(), STANDARD_ISSUER_URI)
                || hasPrefixedProperty(context.getEnvironment(), STANDARD_JWK_SET_URI);

        if (customEntriesConfigured) {
            log.info("Resource-server JWT auto-configuration enabled by custom property '{}'", CUSTOM_ENTRIES_PREFIX);
        } else if (standardJwtConfigured) {
            log.info("Resource-server JWT auto-configuration enabled by standard Spring Security JWT properties");
        } else {
            log.debug("Resource-server JWT auto-configuration not enabled because no JWT resource-server properties were found");
        }
        if (customEntriesConfigured || standardJwtConfigured) {
            return ConditionOutcome.match(ConditionMessage
                    .forCondition("JWT Extended Properties")
                    .found("property")
                    .items(customEntriesConfigured ? CUSTOM_ENTRIES_PREFIX : STANDARD_ISSUER_URI));
        }
        return ConditionOutcome.noMatch(ConditionMessage
                .forCondition("JWT Extended Properties")
                .found("property")
                .items(CUSTOM_ENTRIES_PREFIX));
    }

    private static boolean hasPrefixedProperty(@NonNull final Environment environment, @NonNull final String prefix) {
        if (!(environment instanceof ConfigurableEnvironment configurableEnvironment)) {
            return false;
        }
        for (PropertySource<?> propertySource : configurableEnvironment.getPropertySources()) {
            if (!(propertySource instanceof EnumerablePropertySource<?> enumerablePropertySource)) continue;
            for (String propertyName : enumerablePropertySource.getPropertyNames()) {
                if (propertyName.startsWith(prefix)) {
                    log.trace("Found matching JWT property '{}' for prefix '{}' in property source '{}'", propertyName, prefix, propertySource.getName());
                    return true;
                }
            }
        }
        return false;
    }

}
