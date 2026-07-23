package org.mencom.security.core;

import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class DefaultClaimValueExtractor implements ClaimValueExtractor {

    @Override
    public <T> T extractClaim(Map<String, Object> claims, String claimName, Class<T> claimType) {
        log.trace("Extracting claim '{}' as type '{}'", claimName, claimType.getSimpleName());
        Object claimValue = claims.get(claimName);
        if (claimValue == null) {
            log.trace("Claim '{}' was not present", claimName);
            return null;
        }
        if (!claimType.isInstance(claimValue)) {
            log.error("Claim '{}' had unexpected type '{}'; expected '{}'", claimName, claimValue.getClass().getName(), claimType.getName());
            throw new IllegalArgumentException("Claim value is not of the expected type: " + claimType.getName());
        }
        log.trace("Claim '{}' extracted successfully as type '{}'", claimName, claimType.getSimpleName());
        return claimType.cast(claimValue);
    }

}
