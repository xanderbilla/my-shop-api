package com.shop.categories.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security Configuration for Categories Service
 * 
 * This configuration:
 * 1. Enables method-level security with @PreAuthorize
 * 2. Permits all HTTP requests (security is handled at method level)
 * 3. Disables CSRF (not needed for REST APIs)
 * 4. Sets session policy to STATELESS (JWT-based auth)
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-27
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll() // Allow all requests - security handled by @PreAuthorize
                );

        return http.build();
    }
}