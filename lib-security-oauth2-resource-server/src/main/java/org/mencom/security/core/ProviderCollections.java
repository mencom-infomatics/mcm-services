package org.mencom.security.core;

import org.springframework.security.authentication.AuthenticationManager;

import java.util.List;
import java.util.Map;

public record ProviderCollections(
        AuthenticationManager defaultManager,
        List<AuthenticationManager> nonIssuer,
        Map<String, AuthenticationManager> byIssuer
) {
}
