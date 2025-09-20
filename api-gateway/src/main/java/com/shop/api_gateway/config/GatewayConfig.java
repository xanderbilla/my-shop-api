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
                                .route("auth-public", r -> r.path("/auth/signup", "/auth/signin", "/auth/verify",
                                                "/auth/forgot-password", "/auth/reset-password",
                                                "/auth/resend-otp", "/auth/refresh-token", "/auth/logout")
                                                .uri("lb://auth"))

                                // Protected auth routes (authentication required)
                                .route("auth-protected", r -> r.path("/auth/**")
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
                corsConfig.addAllowedOriginPattern("*");
                corsConfig.addAllowedHeader("*");
                corsConfig.addAllowedMethod("*");

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", corsConfig);

                return new CorsWebFilter(source);
        }
}
