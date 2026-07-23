package org.mencom.security.core;

import lombok.extern.slf4j.Slf4j;
import org.mencom.security.properties.ResourceServerJwtProperties;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;
import java.util.List;

@Slf4j
public class JwtAuthenticationResolver {

    private final ResourceServerJwtProperties jwtProperties;

    public JwtAuthenticationResolver(ResourceServerJwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public Converter<Jwt, AbstractAuthenticationToken> resolveDefault() {
        List<OAuth2ResourceServerProperties.Jwt> mappings = jwtProperties.getEntries();
        log.info("Resolving default JWT authentication converter for {} configured provider entries", mappings.size());
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setPrincipalClaimName("sub");
        log.trace("Configured JWT principal claim as 'sub'");

        if (!hasConfigurationMappings(mappings)) {
            return createDefaultAuthoritiesConverter(converter);
        }

        converter.setJwtGrantedAuthoritiesConverter(jwt -> resolveAuthorities(jwt, mappings));

        log.info("Configured issuer-aware JWT authorities conversion for {} provider mappings", mappings.size());
        return converter;
    }

    private static Converter<Jwt, AbstractAuthenticationToken> createDefaultAuthoritiesConverter(JwtAuthenticationConverter converter) {
        log.info("No authorities claim mappings configured; using Spring Security default JWT authorities conversion");
        JwtGrantedAuthoritiesConverter defaults = new JwtGrantedAuthoritiesConverter();
        converter.setJwtGrantedAuthoritiesConverter(defaults);
        return converter;
    }

    private static java.util.Collection<GrantedAuthority> resolveAuthorities(Jwt jwt, List<OAuth2ResourceServerProperties.Jwt> mappings) {
        String issuer = jwt.getIssuer() == null ? null : jwt.getIssuer().toString();
        log.trace("Evaluating JWT authorities for issuer '{}' against {} configured mappings", issuer, mappings.size());
        OAuth2ResourceServerProperties.Jwt mapping = findMappingForIssuer(mappings, issuer);
        if (mapping != null) {
            return convertAuthorities(jwt, mapping);
        }

        log.info("No issuer-specific authorities mapping matched JWT issuer '{}'; using default authorities conversion", issuer);
        return new JwtGrantedAuthoritiesConverter().convert(jwt);
    }

    private static OAuth2ResourceServerProperties.Jwt findMappingForIssuer(List<OAuth2ResourceServerProperties.Jwt> mappings, String issuer) {
        for (OAuth2ResourceServerProperties.Jwt mapping : mappings) {
            if (mapping.getIssuerUri() != null && mapping.getIssuerUri().equals(issuer)) {
                return mapping;
            }
        }
        return null;
    }

    private static Collection<GrantedAuthority> convertAuthorities(Jwt jwt, OAuth2ResourceServerProperties.Jwt mapping) {
        log.info("Applying configured authorities mapping for issuer '{}'", mapping.getIssuerUri());
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName(mapping.getAuthoritiesClaimName());
        String authorityPrefix = mapping.getAuthorityPrefix() != null ? mapping.getAuthorityPrefix() : "ROLE_";
        authoritiesConverter.setAuthorityPrefix(authorityPrefix);
        log.trace("Configured authorities converter with claim '{}' and prefix '{}'",
                mapping.getAuthoritiesClaimName(),
                authorityPrefix);
        return authoritiesConverter.convert(jwt);
    }

    private static boolean hasConfigurationMappings(List<OAuth2ResourceServerProperties.Jwt> mappings) {
        if (mappings == null || mappings.isEmpty()) {
            return false;
        }
        for (OAuth2ResourceServerProperties.Jwt mapping : mappings) {
            if (mapping != null && mapping.getAuthoritiesClaimName() != null) {
                return true;
            }
        }
        return false;
    }

}
