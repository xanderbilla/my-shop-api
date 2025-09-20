package com.shop.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security Configuration for Auth Service
 * 
 * Features:
 * ✅ Method-level security with @PreAuthorize
 * ✅ Stateless session management (JWT-based)
 * ✅ CORS support for cross-origin requests
 * ✅ CSRF disabled for REST API
 * ✅ Public endpoints for authentication flows
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-20
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF for REST API
                .csrf(csrf -> csrf.disable())

                // Configure session management to be stateless (JWT-based)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Configure authorization
                .authorizeHttpRequests(authz -> authz
                        // Allow public authentication endpoints
                        .requestMatchers("/signup", "/signin", "/verify", "/forgot-password",
                                "/reset-password", "/resend-otp", "/refresh-token")
                        .permitAll()

                        // Allow actuator endpoints for health checks
                        .requestMatchers("/actuator/**").permitAll()

                        // Allow health endpoint
                        .requestMatchers("/health").permitAll()

                        // All other requests will be handled by @PreAuthorize annotations
                        .anyRequest().permitAll())

                // Configure CORS
                .cors(cors -> cors.configurationSource(request -> {
                    var config = new org.springframework.web.cors.CorsConfiguration();
                    config.setAllowCredentials(true);
                    config.addAllowedOriginPattern("*");
                    config.addAllowedHeader("*");
                    config.addAllowedMethod("*");
                    return config;
                }));

        return http.build();
    }
}