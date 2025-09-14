package com.shop.auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class JwtTokenService {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenService.class);

    // In-memory blacklist for tokens (in production, use Redis or database)
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Check if token is valid (not blacklisted)
     * For Cognito tokens, we rely on Cognito's validation
     */
    public boolean isValidToken(String token) {
        if (isTokenBlacklisted(token)) {
            log.warn("Token is blacklisted");
            return false;
        }
        return true;
    }

    /**
     * Blacklist a token (for logout functionality)
     */
    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
        log.info("Token blacklisted successfully");
    }

    /**
     * Check if token is blacklisted
     */
    private boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }

    /**
     * Extract token from Authorization header
     */
    public String extractTokenFromHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /**
     * Extract username from JWT token payload
     * For Cognito tokens, this returns the email (which is used as the username in
     * Cognito)
     */
    public String extractUsernameFromToken(String token) {
        try {
            JsonNode payload = extractPayloadFromToken(token);
            // For Cognito tokens, username is stored in 'username' field (which is email)
            JsonNode usernameNode = payload.get("username");
            if (usernameNode != null) {
                return usernameNode.asText();
            }

            // Fallback to 'email' field if 'username' is not present
            JsonNode emailNode = payload.get("email");
            if (emailNode != null) {
                return emailNode.asText();
            }

            throw new RuntimeException("Username/email not found in token");
        } catch (Exception e) {
            log.error("Error extracting username from token: {}", e.getMessage());
            throw new RuntimeException("Failed to extract username from token", e);
        }
    }

    /**
     * Extract custom username from JWT token payload
     * This looks for the custom:username attribute in Cognito token
     */
    public String extractCustomUsernameFromToken(String token) {
        try {
            JsonNode payload = extractPayloadFromToken(token);
            // For Cognito tokens, custom attributes are stored with 'custom:' prefix
            JsonNode customUsernameNode = payload.get("custom:username");
            if (customUsernameNode != null) {
                return customUsernameNode.asText();
            }

            throw new RuntimeException("Custom username not found in token");
        } catch (Exception e) {
            log.error("Error extracting custom username from token: {}", e.getMessage());
            throw new RuntimeException("Failed to extract custom username from token", e);
        }
    }

    /**
     * Extract email from JWT token payload
     */
    public String extractEmailFromToken(String token) {
        try {
            JsonNode payload = extractPayloadFromToken(token);
            JsonNode emailNode = payload.get("email");
            if (emailNode != null) {
                return emailNode.asText();
            }

            throw new RuntimeException("Email not found in token");
        } catch (Exception e) {
            log.error("Error extracting email from token: {}", e.getMessage());
            throw new RuntimeException("Failed to extract email from token", e);
        }
    }

    /**
     * Extract payload from JWT token
     */
    private JsonNode extractPayloadFromToken(String token) {
        try {
            // Split the token into parts (header.payload.signature)
            String[] tokenParts = token.split("\\.");
            if (tokenParts.length != 3) {
                throw new RuntimeException("Invalid JWT token format");
            }

            // Decode the payload (second part)
            String payload = tokenParts[1];
            byte[] decodedBytes = Base64.getUrlDecoder().decode(payload);
            String decodedPayload = new String(decodedBytes);

            // Parse the JSON payload
            return objectMapper.readTree(decodedPayload);
        } catch (Exception e) {
            log.error("Error extracting payload from token: {}", e.getMessage());
            throw new RuntimeException("Failed to extract payload from token", e);
        }
    }
}