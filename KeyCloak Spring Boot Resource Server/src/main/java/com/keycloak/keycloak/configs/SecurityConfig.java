package com.keycloak.keycloak.configs;

import com.keycloak.keycloak.dto.CustomErrorResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
public class SecurityConfig {

    private final ObjectMapper objectMapper;

    public SecurityConfig(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers("/students").authenticated()
                        .requestMatchers("/students/**").hasRole("admin")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                        .authenticationEntryPoint((request, response, authException) -> {
                            writeJsonResponse(response, HttpServletResponse.SC_UNAUTHORIZED,
                                    "Unauthorized", "Invalid or expired token");
                        })
                )
                .exceptionHandling(ex -> ex

                        .accessDeniedHandler((request, response, accessEx) ->
                                writeJsonResponse(response, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have the required permissions (admin role) to access this resource.")
                        )
                );

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            // Client roles
            Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
            if (resourceAccess != null && resourceAccess.containsKey("springboot_test")) {
                Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get("springboot_test");
                if (clientAccess.containsKey("roles")) {
                    Collection<String> clientRoles = (Collection<String>) clientAccess.get("roles");
                    return clientRoles.stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                            .collect(Collectors.toList());
                }
            }

            // Realm roles fallback
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                Collection<String> roles = (Collection<String>) realmAccess.get("roles");
                return roles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList());
            }

            return java.util.Collections.emptyList();
        });
        return converter;
    }

    private void writeJsonResponse(HttpServletResponse response, int status, String error, String message) throws IOException {
        response.setContentType("application/json");
        response.setStatus(status);
        objectMapper.writeValue(response.getWriter(), new CustomErrorResponse(status, error, message));
        response.getWriter().flush();
    }
}
