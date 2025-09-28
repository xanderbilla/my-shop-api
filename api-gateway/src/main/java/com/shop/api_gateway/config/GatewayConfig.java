package com.shop.api_gateway.config;

import com.shop.api_gateway.filter.AuthFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class GatewayConfig {

        private final AuthFilter authFilter;

        public GatewayConfig(AuthFilter authFilter) {
                this.authFilter = authFilter;
        }

        @Bean
        public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
                return builder.routes()
                                // Public auth routes (no authentication required)
                                // Note: /me, /status, /roles handle their own authentication via @PreAuthorize
                                .route("auth-public", r -> r.path("/api/v1/auth/signup", "/api/v1/auth/signin",
                                                "/api/v1/auth/verify",
                                                "/api/v1/auth/forgot-password", "/api/v1/auth/reset-password",
                                                "/api/v1/auth/resend-otp", "/api/v1/auth/refresh-token",
                                                "/api/v1/auth/logout", "/api/v1/auth/me", "/api/v1/auth/status",
                                                "/api/v1/auth/roles")
                                                .uri("lb://auth"))

                                // Protected auth routes (authentication required) - Note: /me handles its own
                                // auth
                                .route("auth-protected", r -> r.path("/api/v1/auth/**")
                                                .filters(f -> f.filter(authFilter.apply(new AuthFilter.Config())))
                                                .uri("lb://auth"))

                                // Admin routes (ADMIN role required)
                                .route("admin-service", r -> r.path("/admin/**")
                                                .filters(f -> f.filter(authFilter.apply(createAdminConfig())))
                                                .uri("lb://admin"))

                                // Client routes (no authentication required for now)
                                .route("client-service", r -> r.path("/client/**")
                                                .uri("lb://client"))
                                .build();
        }

        private AuthFilter.Config createAdminConfig() {
                AuthFilter.Config config = new AuthFilter.Config();
                config.setRequiredRoles(List.of("ADMIN"));
                return config;
        }

        @Bean
        public CorsWebFilter corsWebFilter() {
                CorsConfiguration corsConfig = new CorsConfiguration();
                corsConfig.setAllowCredentials(true);
                // Allow specific localhost origins for frontend development
                corsConfig.setAllowedOrigins(List.of(
                                "http://localhost:3000",
                                "http://localhost:3001"));
                corsConfig.addAllowedHeader("*");
                corsConfig.addAllowedMethod("*");

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", corsConfig);

                return new CorsWebFilter(source);
        }
}
