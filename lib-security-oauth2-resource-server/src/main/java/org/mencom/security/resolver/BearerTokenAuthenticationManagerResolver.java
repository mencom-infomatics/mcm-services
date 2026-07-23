package org.mencom.security.resolver;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;

import java.util.Locale;

@RequiredArgsConstructor
@Slf4j
@SuppressWarnings("unused")
public class BearerTokenAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {

    private final AuthenticationManagerResolver<HttpServletRequest> delegate;

    @NonNull
    @Override
    public AuthenticationManager resolve(@NonNull HttpServletRequest context) {
        if (isJwt(context)) {
            log.info("Bearer token identified as JWT; delegating to the configured authentication manager resolver");
            return delegate.resolve(context);
        }
        log.info("Bearer token request was rejected because the token is not a JWT");
        throw new IllegalArgumentException("Only JWT is supported as Bearer Token");
    }

    private boolean isJwt(HttpServletRequest context) {
        String authHeader = context.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null) {
            log.trace("No Authorization header found while checking for JWT bearer token");
            return false;
        }

        String trimmedHeader = authHeader.trim();
        if (!trimmedHeader.toLowerCase(Locale.ROOT).startsWith("bearer ")) {
            log.trace("Authorization header is present but is not a Bearer token");
            return false;
        }
        String token = trimmedHeader.substring(7);
        boolean jwt = token.chars().filter(c -> c == '.').count() == 2;
        if (!jwt) {
            log.trace("Bearer token does not appear to be a JWT because it does not contain three segments");
        } else {
            log.trace("Bearer token format looks like a JWT with three segments");
        }
        return jwt;
    }
}
