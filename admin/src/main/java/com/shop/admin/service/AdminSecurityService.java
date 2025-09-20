package com.shop.admin.service;

import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * Custom Security Service for @PreAuthorize expressions
 * 
 * This service provides security validation methods that can be used
 * in @PreAuthorize annotations to check admin access permissions.
 * 
 * Usage in controller methods:
 * @PreAuthorize("@adminSecurityService.isAdmin()")
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-20
 */
@Service("adminSecurityService")
public class AdminSecurityService {

    private final JwtTokenService jwtTokenService;

    public AdminSecurityService(JwtTokenService jwtTokenService) {
        this.jwtTokenService = jwtTokenService;
    }

    /**
     * Validates that the current request comes from an authenticated ADMIN user
     * 
     * This method can be used in @PreAuthorize annotations:
     * @PreAuthorize("@adminSecurityService.isAdmin()")
     * 
     * Security checks:
     * 1. Extracts JWT token from access_token cookie
     * 2. Validates token signature using Cognito JWKS
     * 3. Validates token expiry and issuer
     * 4. Verifies user has ADMIN role in Cognito groups
     * 
     * @return true if user is authenticated admin, false otherwise
     */
    public boolean isAdmin() {
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request == null) {
                System.err.println("SECURITY ALERT: No HTTP request context available");
                return false;
            }

            // Step 1: Extract JWT token from cookies
            String accessToken = extractAccessTokenFromCookies(request);
            if (accessToken == null) {
                System.err.println("SECURITY ALERT: Access denied - No access token found in cookies");
                return false;
            }

            // Step 2: Validate token integrity, signature, expiration, and issuer
            if (!jwtTokenService.isValidToken(accessToken)) {
                System.err.println(
                        "SECURITY ALERT: Access denied - Invalid or expired token (failed JWKS signature verification)");
                return false;
            }

            // Step 3: Extract user groups from Cognito token
            List<String> userGroups = jwtTokenService.extractCognitoGroupsFromToken(accessToken);
            if (userGroups == null || userGroups.isEmpty()) {
                try {
                    String username = jwtTokenService.extractUsernameFromToken(accessToken);
                    System.err.println(
                            "SECURITY ALERT: Access denied - User '" + username + "' has no Cognito groups assigned");
                } catch (Exception e) {
                    System.err.println("SECURITY ALERT: Access denied - No Cognito groups found in token");
                }
                return false;
            }

            // Step 4: Verify ADMIN role specifically
            if (!userGroups.contains("ADMIN")) {
                try {
                    String username = jwtTokenService.extractUsernameFromToken(accessToken);
                    System.err.println("SECURITY ALERT: Access denied - User '" + username
                            + "' attempted admin access with groups " + userGroups + " (ADMIN group required)");
                } catch (Exception e) {
                    System.err.println("SECURITY ALERT: Access denied - User has groups " + userGroups
                            + " but ADMIN group required");
                }
                return false;
            }

            // Access granted - log successful admin access
            try {
                String adminUsername = jwtTokenService.extractUsernameFromToken(accessToken);
                System.out.println("ADMIN ACCESS GRANTED: User '" + adminUsername
                        + "' authenticated successfully with ADMIN group");
            } catch (Exception e) {
                System.out.println("ADMIN ACCESS GRANTED: Admin user authenticated successfully");
            }

            return true;
        } catch (Exception e) {
            System.err.println("SECURITY ERROR: Exception during admin validation: " + e.getMessage());
            return false;
        }
    }

    /**
     * Gets the current admin user ID for audit logging
     * 
     * @return Admin username from JWT token, or "admin" as fallback
     */
    public String getCurrentAdminId() {
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request == null) {
                return "admin";
            }

            String accessToken = extractAccessTokenFromCookies(request);
            if (accessToken != null && jwtTokenService.isValidToken(accessToken)) {
                return jwtTokenService.extractUsernameFromToken(accessToken);
            }
        } catch (Exception e) {
            System.err.println("Failed to extract admin ID from token: " + e.getMessage());
        }
        return "admin"; // fallback
    }

    /**
     * Additional validation method to explicitly check ADMIN group membership
     * Can be used in complex security expressions
     */
    public boolean hasAdminGroup() {
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request == null) {
                return false;
            }

            String accessToken = extractAccessTokenFromCookies(request);
            if (accessToken == null || !jwtTokenService.isValidToken(accessToken)) {
                return false;
            }

            List<String> userGroups = jwtTokenService.extractCognitoGroupsFromToken(accessToken);
            return userGroups != null && userGroups.contains("ADMIN");
        } catch (Exception e) {
            System.err.println("Error checking admin group: " + e.getMessage());
            return false;
        }
    }

    /**
     * Validates admin access with detailed audit logging
     */
    public boolean validateAdminAccess() {
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request == null) {
                return false;
            }

            String accessToken = extractAccessTokenFromCookies(request);
            if (accessToken == null) {
                return false;
            }

            if (!jwtTokenService.isValidToken(accessToken)) {
                return false;
            }

            List<String> userGroups = jwtTokenService.extractCognitoGroupsFromToken(accessToken);
            String username = jwtTokenService.extractUsernameFromToken(accessToken);

            boolean hasAdminAccess = userGroups != null && userGroups.contains("ADMIN");

            // Detailed audit logging
            System.out.println("ADMIN ACCESS VALIDATION: User '" + username +
                    "', Groups: " + userGroups +
                    ", Access Granted: " + hasAdminAccess);

            return hasAdminAccess;
        } catch (Exception e) {
            System.err.println("Admin access validation error: " + e.getMessage());
            return false;
        }
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