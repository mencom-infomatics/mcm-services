package org.mencom.server.eureka.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.boot.health.actuate.endpoint.HealthEndpoint;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
public class SecurityConfig {

    @Bean
    @SuppressWarnings("SpringSecurityDisableCsrfProtection")
    SecurityFilterChain securityFilterChain(
            HttpSecurity httpSecurity,
            AuthenticationManagerResolver<HttpServletRequest> authManagerResolver
    ) {

        log.info("Configuring Eureka server security with JWT authentication");
        httpSecurity
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(EndpointRequest.to(HealthEndpoint.class, InfoEndpoint.class)).permitAll()
                        .anyRequest().permitAll());
        httpSecurity.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authManagerResolver));

        try {
            return httpSecurity.build();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to build Eureka server SecurityFilterChain", ex);
        }
    }
}
