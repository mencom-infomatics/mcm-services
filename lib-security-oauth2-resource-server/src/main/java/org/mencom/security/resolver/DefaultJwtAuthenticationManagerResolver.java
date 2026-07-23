package org.mencom.security.resolver;

import com.nimbusds.jwt.JWTParser;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.mencom.security.core.JwtAuthenticationResolver;
import org.mencom.security.core.NonIssuerRoutingAuthenticationManager;
import org.mencom.security.core.ProviderCollections;
import org.mencom.security.properties.ResourceServerJwtProperties;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;

import java.util.*;

import static org.mencom.security.utils.ResourceServerUtils.oauth2InvalidToken;

@Slf4j
public class DefaultJwtAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {

    private final AuthenticationManager defaultManager;
    private final List<AuthenticationManager> nonIssuerManagers;
    private final Map<String, AuthenticationManager> managerByIssuer;

    @SuppressWarnings("unused")
    public DefaultJwtAuthenticationManagerResolver(ResourceServerJwtProperties properties, JwtAuthenticationResolver converterResolver) {
        this(properties, converterResolver, List.of());
    }

    public DefaultJwtAuthenticationManagerResolver(ResourceServerJwtProperties properties, JwtAuthenticationResolver converterResolver, List<OAuth2TokenValidator<Jwt>> additionalValidators) {
        ProviderCollections collections = buildManagers(properties, converterResolver, additionalValidators);
        this.defaultManager = collections.defaultManager();
        this.nonIssuerManagers = collections.nonIssuer();
        this.managerByIssuer = collections.byIssuer();
        log.info("Initialized JWT authentication manager resolver with {} issuer-bound providers and {} non-issuer providers",
                this.managerByIssuer.size(), this.nonIssuerManagers.size());
    }

    @NonNull
    @Override
    public AuthenticationManager resolve(@NonNull HttpServletRequest context) {
        String token = bearerToken(context);
        if (token == null) {
            log.debug("No Bearer token found on request; using default authentication manager");
            return defaultManager;
        }

        log.trace("Bearer token detected on request; attempting issuer-based routing");

        Optional<String> issuer = issuerFromToken(token);
        if (issuer.isPresent()) {
            AuthenticationManager byIssuer = managerByIssuer.get(issuer.get());
            if (byIssuer != null) {
                log.info("Resolved JWT authentication manager for issuer '{}'", issuer.get());
                return byIssuer;
            }
            log.debug("No configured authentication manager found for issuer '{}'", issuer.get());
            throw oauth2InvalidToken("No JWT AuthenticationManager Configured for issuer " + issuer.get());
        }

        if (nonIssuerManagers.isEmpty()) {
            log.debug("JWT does not contain an issuer and no non-issuer providers are configured");
            throw oauth2InvalidToken("Incoming JWT doesn't contain an 'iss' and no provider is configured for non-issuer configuration");
        }

        if (nonIssuerManagers.size() == 1) {
            log.info("JWT does not contain an issuer; using the single configured non-issuer authentication manager");
            return nonIssuerManagers.getFirst();
        }

        log.info("JWT does not contain an issuer; routing through {} non-issuer authentication managers", nonIssuerManagers.size());
        return new NonIssuerRoutingAuthenticationManager(nonIssuerManagers);
    }

    private static String bearerToken(@NonNull HttpServletRequest context) {
        String authorization = context.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization == null) {
            log.trace("Request did not contain an Authorization header");
            return null;
        }

        String trimmedAuthorization = authorization.trim();
        if (!trimmedAuthorization.toLowerCase(Locale.ROOT).startsWith("bearer ")) {
            log.trace("Authorization header is present but does not contain a Bearer token");
            return null;
        }

        String token = trimmedAuthorization.substring(7).trim();
        log.trace("Bearer token extracted from Authorization header; tokenPresent={}", !token.isBlank());
        return token.isBlank() ? null : token;
    }

    private static Optional<String> issuerFromToken(@NonNull String token) {
        try {
            String issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();
            if (issuer == null) {
                log.trace("JWT parsed successfully but no issuer claim was present");
                return Optional.empty();
            }
            if (issuer.isBlank()) {
                throw oauth2InvalidToken("Incoming JWT 'iss' claim must be a non-blank string");
            }
            log.trace("JWT issuer claim parsed successfully: '{}'", issuer);
            return Optional.of(issuer);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            log.debug("Failed to parse JWT issuer claim for authentication manager routing", ex);
            throw oauth2InvalidToken("Failed to parse JWT claims for provider routing", ex);
        }
    }

    private static ProviderCollections buildManagers(ResourceServerJwtProperties properties, JwtAuthenticationResolver converterResolver, List<OAuth2TokenValidator<Jwt>> additionalValidators) {
        Map<String, AuthenticationManager> managersByIssuer = new HashMap<>();
        List<AuthenticationManager> nonIssuerManagers = new ArrayList<>();
        AuthenticationManager defaultManager = null;

        List<OAuth2ResourceServerProperties.Jwt> providers = properties.getEntries();
        log.info("Building JWT authentication managers from {} configured provider entries", providers.size());
        for (OAuth2ResourceServerProperties.Jwt provider : providers) {
            JwtDecoder jwtDecoder = buildJwtDecoder(provider, additionalValidators);
            JwtAuthenticationProvider jwtAuthProvider = new JwtAuthenticationProvider(jwtDecoder);
            jwtAuthProvider.setJwtAuthenticationConverter(converterResolver.resolveDefault());
            AuthenticationManager authManager = new ProviderManager(jwtAuthProvider);

            log.trace("Created authentication manager for provider issuer='{}', jwkSetUriPresent={}, audiences={}, additionalValidators={}",
                    provider.getIssuerUri(),
                    StringUtils.isNotBlank(provider.getJwkSetUri()),
                    provider.getAudiences().size(),
                    additionalValidators == null ? 0 : additionalValidators.size());

            if (defaultManager == null) {
                defaultManager = authManager;
                log.info("Selected first configured provider as the default authentication manager");
            }

            if (StringUtils.isBlank(provider.getIssuerUri())) {
                nonIssuerManagers.add(authManager);
                log.info("Registered non-issuer JWT authentication manager");
                continue;
            }

            AuthenticationManager previous = managersByIssuer.put(provider.getIssuerUri(), authManager);
            if (previous != null) {
                throw new IllegalStateException("Duplicate issuer URI found: " + provider.getIssuerUri());
            }
            log.info("Registered JWT authentication manager for issuer '{}'", provider.getIssuerUri());
        }

        if (defaultManager == null) {
            throw new IllegalStateException("No default authentication manager could be created. Configure at least one provider.");
        }

        log.info("Finished building JWT authentication managers: byIssuer={}, nonIssuer={}, defaultConfigured={}",
                managersByIssuer.size(), nonIssuerManagers.size(), true);

        return new ProviderCollections(
                defaultManager,
                Collections.unmodifiableList(nonIssuerManagers),
                Collections.unmodifiableMap(managersByIssuer)
        );
    }

    private static JwtDecoder buildJwtDecoder(OAuth2ResourceServerProperties.Jwt provider, List<OAuth2TokenValidator<Jwt>> additionalValidators) {
        OAuth2TokenValidator<Jwt> defaultValidator = StringUtils.isBlank(provider.getIssuerUri())
                ? JwtValidators.createDefault()
                : JwtValidators.createDefaultWithIssuer(provider.getIssuerUri());

        if (StringUtils.isNotBlank(provider.getJwkSetUri())) {
            log.trace("Building NimbusJwtDecoder with JWK set URI for issuer '{}' and algorithms {}", provider.getIssuerUri(), provider.getJwsAlgorithms());
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(provider.getJwkSetUri())
                    .jwsAlgorithms(signatureAlgorithms -> {
                        List<String> jwsAlgorithms = provider.getJwsAlgorithms();
                        jwsAlgorithms.forEach(algo -> signatureAlgorithms.add(SignatureAlgorithm.from(algo)));
                    })
                    .build();
            decoder.setJwtValidator(composeValidators(defaultValidator, provider.getAudiences(), additionalValidators));
            return decoder;
        }

        log.trace("Building NimbusJwtDecoder with issuer location for issuer '{}'", provider.getIssuerUri());
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation(provider.getIssuerUri()).build();
        decoder.setJwtValidator(composeValidators(defaultValidator, provider.getAudiences(), additionalValidators));
        return decoder;
    }

    private static OAuth2TokenValidator<Jwt> composeValidators(OAuth2TokenValidator<Jwt> defaultValidator, List<String> audiences, List<OAuth2TokenValidator<Jwt>> additionalValidators) {
        if ((audiences == null || audiences.isEmpty()) && (additionalValidators == null || additionalValidators.isEmpty())) {
            log.trace("Using default JWT validator without additional audience or custom validators");
            return defaultValidator;
        }

        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(defaultValidator);

        if (audiences != null && !audiences.isEmpty()) {
            validators.add(new JwtClaimValidator<List<String>>(JwtClaimNames.AUD, aud -> aud != null && !Collections.disjoint(aud, audiences)));
        }

        if (additionalValidators != null && !additionalValidators.isEmpty()) {
            validators.addAll(additionalValidators);
        }

        log.trace("Composed JWT validators: audiences={}, additionalValidators={}",
                audiences == null ? 0 : audiences.size(),
                additionalValidators == null ? 0 : additionalValidators.size());
        return new DelegatingOAuth2TokenValidator<>(validators);
    }

}
