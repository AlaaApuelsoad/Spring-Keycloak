package org.example.alaa.keycloak;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Custom JWT authentication converter for extracting user roles from Keycloak JWT tokens.
 * <p>
 * This class is responsible for mapping claims in the JWT token to Spring Security GrantedAuthorities
 * and setting the principal (usually the username) for authentication.
 * </p>
 */
@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    /**
     * Default converter that extracts roles from the standard 'scope' or 'authorities' claims in JWT.
     */
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    /**
     * JWT claim used to identify the authenticated principal (typically username).
     */
    @Value("${jwt.auth.principle-attribute}")
    private String principalAttribute;

    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;

    /**
     * Converts a {@link Jwt} into an {@link AbstractAuthenticationToken}, combining standard and custom roles.
     *
     * @param jwt the decoded JWT token
     * @return a {@link JwtAuthenticationToken} containing user authorities and principal
     */
    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractResourceRoles(jwt).stream()
        ).collect(Collectors.toSet());

        return new JwtAuthenticationToken(jwt, authorities, getPrincipalName(jwt));
    }

    /**
     * Extracts roles from the "resource_access" section of the JWT, specific to a given client (e.g., 'alaa-rest-api').
     *
     * @param jwt the JWT token
     * @return a collection of {@link GrantedAuthority} derived from the client roles
     */
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess == null || resourceAccess.get(resourceId) == null) {
            return Set.of();
        }

        Map<String, Object> resource = (Map<String, Object>) resourceAccess.get(resourceId);
        Collection<String> roles = (Collection<String>) resource.get("roles");

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }

    /**
     * Retrieves the principal (user identity) from the JWT based on a configurable claim attribute.
     *
     * @param jwt the JWT token
     * @return the principal name (e.g., username)
     */
    private String getPrincipalName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;
        if (principalAttribute != null) {
            claimName = principalAttribute;
        }
        return jwt.getClaimAsString(claimName);
    }
}
