package org.mencom.security.core;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;

import java.util.List;
import java.util.Objects;

import static org.mencom.security.utils.ResourceServerUtils.oauth2InvalidToken;

@RequiredArgsConstructor
@Slf4j
public class NonIssuerRoutingAuthenticationManager implements AuthenticationManager {

    private final List<AuthenticationManager> delegates;

    @NonNull
    @Override
    public Authentication authenticate(@NonNull Authentication authentication) throws AuthenticationException {
        log.debug("Attempting authentication against {} non-issuer JWT providers", delegates.size());

        int successCount = 0;
        Authentication singleSuccess = null;
        AuthenticationException lastFailure = null;
        int delegateIndex = 0;

        for (AuthenticationManager delagate : delegates) {
            try {
                delegateIndex++;
                log.trace("Authenticating JWT with non-issuer provider {} of {}", delegateIndex, delegates.size());
                singleSuccess = delagate.authenticate(freshAuthentication(authentication));
                successCount++;
            } catch (AuthenticationException ex) {
                lastFailure = ex;
                log.trace("Non-issuer provider {} rejected the JWT: {}", delegateIndex, ex.getMessage());
            }
        }

        if (successCount == 1) {
            log.info("JWT was authenticated by exactly one non-issuer provider");
            return Objects.requireNonNull(singleSuccess);
        }

        if (successCount > 1) {
            log.info("JWT matched multiple non-issuer providers ({})", successCount);
            throw oauth2InvalidToken("Incoming JWT matched multiple jwk-set-uri providers");
        }
        if (lastFailure != null) {
            log.debug("All non-issuer providers rejected the JWT; rethrowing the last authentication failure");
            throw lastFailure;
        }

        log.info("No non-issuer provider could authenticate the incoming JWT");
        throw oauth2InvalidToken("No non-issuer JWT provider could authenticate the incoming token");
    }

    private Authentication freshAuthentication(Authentication authentication) {
        if (authentication instanceof BearerTokenAuthenticationToken bearer) {
            return new BearerTokenAuthenticationToken(bearer.getToken());
        }
        return authentication;
    }

}
