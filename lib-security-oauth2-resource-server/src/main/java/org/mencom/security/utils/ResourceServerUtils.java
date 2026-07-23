package org.mencom.security.utils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ResourceServerUtils {

    public static OAuth2AuthenticationException oauth2InvalidToken(String description) {
        return oauth2InvalidToken(description, null);
    }

    public static OAuth2AuthenticationException oauth2InvalidToken(String description, Throwable cause) {
        if (cause == null) {
            return new OAuth2AuthenticationException(BearerTokenErrors.invalidToken(description));
        }
        return new OAuth2AuthenticationException(BearerTokenErrors.invalidToken(description), cause);
    }

}
