package com.shop.admin.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Service
public class JwtTokenService {

    private final ObjectMapper objectMapper;

    public JwtTokenService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Extract username from JWT token
     */
    public String extractUsername(String token) {
        try {
            Map<String, Object> payload = decodeJwtPayload(token);
            return (String) payload.get("username");
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract username from token", e);
        }
    }

    /**
     * Extract Cognito groups from JWT token
     */
    @SuppressWarnings("unchecked")
    public List<String> extractCognitoGroups(String token) {
        try {
            Map<String, Object> payload = decodeJwtPayload(token);
            return (List<String>) payload.get("cognito:groups");
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract cognito groups from token", e);
        }
    }

    /**
     * Check if user has specific group
     */
    public boolean hasGroup(String token, String groupName) {
        try {
            List<String> groups = extractCognitoGroups(token);
            return groups != null && groups.contains(groupName);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check if user has admin privileges
     */
    public boolean isAdmin(String token) {
        return hasGroup(token, "ADMIN");
    }

    /**
     * Check if user has user privileges
     */
    public boolean isUser(String token) {
        return hasGroup(token, "USER");
    }

    /**
     * Validate basic token structure and extract claims
     */
    public boolean isValidToken(String token) {
        try {
            if (token == null || token.trim().isEmpty()) {
                return false;
            }

            // Basic JWT structure validation (3 parts separated by dots)
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return false;
            }

            // Try to decode payload to ensure it's valid JSON
            decodeJwtPayload(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get all token information for debugging
     */
    public Map<String, Object> getTokenInfo(String token) {
        try {
            Map<String, Object> payload = decodeJwtPayload(token);
            return Map.of(
                    "username", payload.get("username"),
                    "cognito:groups", payload.get("cognito:groups"),
                    "sub", payload.get("sub"),
                    "exp", payload.get("exp"),
                    "iat", payload.get("iat"),
                    "token_use", payload.get("token_use"));
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract token info", e);
        }
    }

    /**
     * Decode JWT payload (without signature verification)
     * Note: This is for development/testing. In production, use proper JWT
     * libraries with signature verification.
     */
    private Map<String, Object> decodeJwtPayload(String token) {
        try {
            String[] chunks = token.split("\\.");
            if (chunks.length != 3) {
                throw new IllegalArgumentException("Invalid JWT token format");
            }

            // Decode the payload (second part)
            String payload = chunks[1];

            // Add padding if necessary
            while (payload.length() % 4 != 0) {
                payload += "=";
            }

            byte[] decodedBytes = Base64.getUrlDecoder().decode(payload);
            String decodedPayload = new String(decodedBytes, StandardCharsets.UTF_8);

            // Parse JSON
            JsonNode jsonNode = objectMapper.readTree(decodedPayload);
            @SuppressWarnings("unchecked")
            Map<String, Object> payloadMap = objectMapper.convertValue(jsonNode, Map.class);
            return payloadMap;
        } catch (Exception e) {
            throw new RuntimeException("Failed to decode JWT payload", e);
        }
    }
}