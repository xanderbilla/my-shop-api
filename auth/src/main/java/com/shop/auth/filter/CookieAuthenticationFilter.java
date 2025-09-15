package com.shop.auth.filter;

import com.shop.auth.service.JwtTokenService;
import com.shop.auth.util.CookieUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CookieAuthenticationFilter extends OncePerRequestFilter {

    private final CookieUtil cookieUtil;
    private final JwtTokenService jwtTokenService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, 
                                  @NonNull HttpServletResponse response, 
                                  @NonNull FilterChain filterChain) throws ServletException, IOException {
        
        try {
            // Skip authentication for public endpoints
            String requestPath = request.getRequestURI();
            if (isPublicEndpoint(requestPath)) {
                filterChain.doFilter(request, response);
                return;
            }

            // Get token from cookie
            String token = cookieUtil.getAccessTokenFromCookies(request).orElse(null);
            
            if (token != null) {
                try {
                    // Validate token and add user info to request attributes
                    if (jwtTokenService.isValidToken(token)) {
                        String username = jwtTokenService.extractUsernameFromToken(token);
                        request.setAttribute("authenticated_user", username);
                        request.setAttribute("access_token", token);
                    } else {
                        // Token is invalid, clear it
                        cookieUtil.clearAuthCookies(response);
                    }
                } catch (Exception e) {
                    log.error("Token validation failed", e);
                    // Token is invalid, clear it
                    cookieUtil.clearAuthCookies(response);
                }
            }
        } catch (Exception e) {
            // Log error but continue with filter chain
            log.error("Error in cookie authentication filter", e);
        }
        
        filterChain.doFilter(request, response);
    }

    /**
     * Check if the endpoint is public (doesn't require authentication)
     */
    private boolean isPublicEndpoint(String path) {
        String[] publicPaths = {
            "/api/v1/auth/signup",
            "/api/v1/auth/signin",
            "/api/v1/auth/verify",
            "/api/v1/auth/forgot-password",
            "/api/v1/auth/reset-password",
            "/api/v1/auth/resend-otp",
            "/api/v1/auth/refresh-token",
            "/api/v1/auth/status",
            "/actuator/health"
        };
        
        for (String publicPath : publicPaths) {
            if (path.startsWith(publicPath)) {
                return true;
            }
        }
        
        return false;
    }
}