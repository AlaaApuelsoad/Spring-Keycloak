package org.example.alaa.keycloak;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration class for securing REST APIs using JWT tokens from Keycloak.
 * <p>
 * This class defines the security filter chain that:
 * <ul>
 *     <li>Disables CSRF protection (suitable for stateless APIs).</li>
 *     <li>Requires authentication for all incoming requests.</li>
 *     <li>Uses a custom {@link JwtAuthConverter} to extract roles from JWTs.</li>
 *     <li>Configures the application to be stateless (no session stored).</li>
 * </ul>
 * </p>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    /**
     * Custom JWT authentication converter that maps Keycloak roles to Spring Security authorities.
     */
    private final JwtAuthConverter jwtAuthConverter;

    /**
     * Defines the security filter chain to enforce stateless JWT-based authentication for all endpoints.
     *
     * @param http the {@link HttpSecurity} object to configure
     * @return the configured {@link SecurityFilterChain}
     * @throws Exception in case of any configuration errors
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable());

        http.authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated());

        http.oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwtConfigurer ->
                        jwtConfigurer.jwtAuthenticationConverter(jwtAuthConverter)));

        http.sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
