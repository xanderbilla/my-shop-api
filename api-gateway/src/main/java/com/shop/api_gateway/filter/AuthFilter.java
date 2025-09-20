package com.shop.api_gateway.filter;

import com.shop.api_gateway.service.JwtTokenService;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Custom Gateway Filter for JWT Authentication and Authorization
 * 
 * This filter validates JWT tokens and checks user roles before
 * allowing requests to reach the target microservices.
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-20
 */
@Component
public class AuthFilter extends AbstractGatewayFilterFactory<AuthFilter.Config> {

    private final JwtTokenService jwtTokenService;

    public AuthFilter(JwtTokenService jwtTokenService) {
        super(Config.class);
        this.jwtTokenService = jwtTokenService;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            // Extract token from cookies
            String token = extractTokenFromCookies(request);

            if (token == null) {
                System.err.println("GATEWAY SECURITY: No access token found for " + request.getPath());
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }

            // Validate token
            if (!jwtTokenService.isValidToken(token)) {
                System.err.println("GATEWAY SECURITY: Invalid token for " + request.getPath());
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }

            // Check role requirements
            if (config.getRequiredRoles() != null && !config.getRequiredRoles().isEmpty()) {
                boolean hasRequiredRole = false;
                for (String role : config.getRequiredRoles()) {
                    if (jwtTokenService.hasAnyRole(token, role)) {
                        hasRequiredRole = true;
                        break;
                    }
                }

                if (!hasRequiredRole) {
                    String username = jwtTokenService.extractUsernameFromToken(token);
                    System.err.println("GATEWAY SECURITY: User '" + username + "' lacks required roles " +
                            config.getRequiredRoles() + " for " + request.getPath());
                    response.setStatusCode(HttpStatus.FORBIDDEN);
                    return response.setComplete();
                }
            }

            // Log successful authorization
            String username = jwtTokenService.extractUsernameFromToken(token);
            List<String> userRoles = jwtTokenService.extractCognitoGroupsFromToken(token);
            System.out.println("GATEWAY ACCESS GRANTED: User '" + username + "' with roles " + userRoles +
                    " accessing " + request.getPath());

            // Add user info to request headers for downstream services
            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-Name", username)
                    .header("X-User-Roles", String.join(",", userRoles))
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        };
    }

    private String extractTokenFromCookies(ServerHttpRequest request) {
        List<String> cookies = request.getHeaders().get("Cookie");
        if (cookies != null) {
            for (String cookie : cookies) {
                String[] cookieParts = cookie.split(";");
                for (String part : cookieParts) {
                    String[] keyValue = part.trim().split("=", 2);
                    if (keyValue.length == 2 && "access_token".equals(keyValue[0])) {
                        return keyValue[1];
                    }
                }
            }
        }
        return null;
    }

    public static class Config {
        private List<String> requiredRoles;

        public List<String> getRequiredRoles() {
            return requiredRoles;
        }

        public void setRequiredRoles(List<String> requiredRoles) {
            this.requiredRoles = requiredRoles;
        }
    }
}