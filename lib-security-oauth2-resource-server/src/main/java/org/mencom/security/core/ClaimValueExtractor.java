package org.mencom.security.core;

import java.util.Map;

public interface ClaimValueExtractor {

    <T> T extractClaim(Map<String, Object> claims, String claimName, Class<T> claimType);

}
