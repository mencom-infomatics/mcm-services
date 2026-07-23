package org.mencom.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.mencom.security.core.ClaimValueExtractor;
import org.mencom.security.core.DefaultClaimValueExtractor;
import org.mencom.security.core.JwtAuthenticationResolver;
import org.mencom.security.core.ResourceServerJwtCondition;
import org.mencom.security.properties.ResourceServerJwtProperties;
import org.mencom.security.resolver.DefaultJwtAuthenticationManagerResolver;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

@Slf4j
@AutoConfiguration
@Conditional(ResourceServerJwtCondition.class)
@ConditionalOnClass(OAuth2ResourceServerProperties.class)
@EnableConfigurationProperties(ResourceServerJwtProperties.class)
public class ResourceServerJwtConfiguration {

    @Bean
    @ConditionalOnMissingBean
    ClaimValueExtractor claimValueExtractor() {
        log.info("Registering default ClaimValueExtractor implementation");
        log.trace("ClaimValueExtractor will use the built-in type-safe claim extraction strategy");
        return new DefaultClaimValueExtractor();
    }

    @Bean
    @ConditionalOnMissingBean
    JwtAuthenticationResolver jwtAuthenticationResolver(ResourceServerJwtProperties properties) {
        log.info("Registering JwtAuthenticationResolver for {} configured JWT provider entries", properties.getEntries().size());
        log.trace("JWT authority mapping entries: {}", properties.getEntries().stream()
                .map(entry -> entry.getIssuerUri() == null ? "<non-issuer>" : entry.getIssuerUri())
                .toList());
        return new JwtAuthenticationResolver(properties);
    }


    @Bean
    @ConditionalOnMissingBean(name = "jwtAuthenticationConverter")
    public Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter(JwtAuthenticationResolver resolver) {
        log.debug("Registering default JWT authentication converter bean");
        return resolver.resolveDefault();
    }

    @Bean("jwtAuthenticationManagerResolver")
    @ConditionalOnMissingBean(name = "jwtAuthenticationManagerResolver")
    AuthenticationManagerResolver<HttpServletRequest> jwtAuthenticationManagerResolver(
            ResourceServerJwtProperties properties,
            JwtAuthenticationResolver converterResolver,
            ObjectProvider<OAuth2TokenValidator<Jwt>> additionalValidators
    ) {
        var validators = additionalValidators.orderedStream().toList();
        log.info("Registering JWT authentication manager resolver with {} configured JWT provider entries and {} additional token validators",
                properties.getEntries().size(), validators.size());
        log.trace("JWT manager resolver will evaluate {} provider entries at runtime", properties.getEntries().size());
        return new DefaultJwtAuthenticationManagerResolver(
                properties,
                converterResolver,
                validators);
    }

}
