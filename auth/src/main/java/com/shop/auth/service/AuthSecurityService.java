package com.shop.auth.service;

import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * Custom Security Service for @PreAuthorize expressions in Auth Service
 * 
 * This service provides security validation methods that can be used
 * in @PreAuthorize annotations to check authentication and role-based access.
 * 
 * Usage in controller methods:
 * @PreAuthorize("@authSecurityService.isAuthenticated()")
 * @PreAuthorize("@authSecurityService.hasRole('ADMIN')")
 * @PreAuthorize("@authSecurityService.hasAnyRole('ADMIN', 'SUPPORT')")
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-20
 */
@Service("authSecurityService")
public class AuthSecurityService {

    private final JwtTokenService jwtTokenService;

    public AuthSecurityService(JwtTokenService jwtTokenService) {
        this.jwtTokenService = jwtTokenService;
    }

    /**
     * Validates that the current request comes from an authenticated user
     * 
     * This method can be used in @PreAuthorize annotations:
     * @PreAuthorize("@authSecurityService.isAuthenticated()")
     * 
     * Security checks:
     * 1. Extracts JWT token from access_token cookie
     * 2. Validates token is not expired/tampered
     * 
     * @return true if user is authenticated, false otherwise
     */
    public boolean isAuthenticated() {
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request == null) {
                System.err.println("SECURITY ALERT: No HTTP request context available");
                return false;
            }

            // Extract JWT token from cookies
            String accessToken = extractAccessTokenFromCookies(request);
            if (accessToken == null) {
                System.err.println("SECURITY ALERT: Access denied - No access token found in cookies");
                return false;
            }

            // Validate token integrity and expiration
            if (!jwtTokenService.isValidToken(accessToken)) {
                System.err.println("SECURITY ALERT: Access denied - Invalid or expired token");
                return false;
            }

            // Log successful authentication
            try {
                String username = jwtTokenService.extractUsernameFromToken(accessToken);
                System.out.println("USER AUTHENTICATED: User '" + username + "' validated successfully");
            } catch (Exception e) {
                System.out.println("USER AUTHENTICATED: Valid user token verified");
            }

            return true;
        } catch (Exception e) {
            System.err.println("SECURITY ERROR: Exception during authentication validation: " + e.getMessage());
            return false;
        }
    }

    /**
     * Validates that the current user has the specified role
     * 
     * @PreAuthorize("@authSecurityService.hasRole('ADMIN')")
     * 
     * @param role The required role (ADMIN, USER, SUPPORT)
     * @return true if user has the role, false otherwise
     */
    public boolean hasRole(String role) {
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request == null) {
                return false;
            }

            String accessToken = extractAccessTokenFromCookies(request);
            if (accessToken == null || !jwtTokenService.isValidToken(accessToken)) {
                return false;
            }

            // Extract Cognito groups from token
            List<String> cognitoGroups = jwtTokenService.extractCognitoGroupsFromToken(accessToken);
            boolean hasRole = cognitoGroups.contains(role.toUpperCase());

            if (hasRole) {
                try {
                    String username = jwtTokenService.extractUsernameFromToken(accessToken);
                    System.out.println("ROLE ACCESS GRANTED: User '" + username + "' has role '" + role + "'");
                } catch (Exception e) {
                    System.out.println("ROLE ACCESS GRANTED: User has role '" + role + "'");
                }
            } else {
                try {
                    String username = jwtTokenService.extractUsernameFromToken(accessToken);
                    System.err.println("ROLE ACCESS DENIED: User '" + username + "' lacks role '" + role + "'");
                } catch (Exception e) {
                    System.err.println("ROLE ACCESS DENIED: User lacks role '" + role + "'");
                }
            }

            return hasRole;
        } catch (Exception e) {
            System.err.println("SECURITY ERROR: Exception during role validation: " + e.getMessage());
            return false;
        }
    }

    /**
     * Validates that the current user has any of the specified roles
     * 
     * @PreAuthorize("@authSecurityService.hasAnyRole('ADMIN', 'SUPPORT')")
     * 
     * @param roles Array of acceptable roles
     * @return true if user has any of the roles, false otherwise
     */
    public boolean hasAnyRole(String... roles) {
        for (String role : roles) {
            if (hasRole(role)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the current user is an admin
     * 
     * @PreAuthorize("@authSecurityService.isAdmin()")
     * 
     * @return true if user has ADMIN role, false otherwise
     */
    public boolean isAdmin() {
        return hasRole("ADMIN");
    }

    /**
     * Gets the current authenticated user ID for audit logging
     * 
     * @return Username from JWT token, or "anonymous" as fallback
     */
    public String getCurrentUserId() {
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request == null) {
                return "anonymous";
            }

            String accessToken = extractAccessTokenFromCookies(request);
            if (accessToken != null && jwtTokenService.isValidToken(accessToken)) {
                return jwtTokenService.extractUsernameFromToken(accessToken);
            }
        } catch (Exception e) {
            System.err.println("Failed to extract user ID from token: " + e.getMessage());
        }
        return "anonymous"; // fallback
    }

    private HttpServletRequest getCurrentRequest() {
        try {
            ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder
                    .getRequestAttributes();
            return requestAttributes != null ? requestAttributes.getRequest() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private String extractAccessTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("access_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}