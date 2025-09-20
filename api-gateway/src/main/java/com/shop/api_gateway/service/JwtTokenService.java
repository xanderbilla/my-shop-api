package com.shop.api_gateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enhanced JWT Token Service for API Gateway with Cognito JWKS Validation
 * 
 * This service provides comprehensive JWT validation including:
 * - Signature validation using Cognito JWKS
 * - Token expiry (exp) verification
 * - Issuer check (iss) validation
 * - Token format and structure validation
 * 
 * @author Vikas Singh
 * @version 2.0
 * @since 2025-09-20
 */
@Service
public class JwtTokenService {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final WebClient webClient;
    private final Map<String, PublicKey> keyCache = new ConcurrentHashMap<>();

    @Value("${aws.cognito.region:us-east-1}")
    private String cognitoRegion;

    @Value("${aws.cognito.userPoolId:us-east-1_Qst5LEWYk}")
    private String userPoolId;

    @Value("${aws.cognito.clientId:72it13gri0bd0nm3rpj5b37a7q}")
    private String clientId;

    private String expectedIssuer;
    private String jwksUrl;

    public JwtTokenService() {
        this.webClient = WebClient.builder().build();
    }

    /**
     * Comprehensive JWT token validation with Cognito JWKS verification
     */
    public boolean isValidToken(String token) {
        try {
            if (token == null || token.trim().isEmpty()) {
                System.err.println("JWT Validation Failed: Token is null or empty");
                return false;
            }

            // Initialize URLs if not done yet
            initializeUrls();

            // Parse JWT
            String[] tokenParts = token.split("\\.");
            if (tokenParts.length != 3) {
                System.err.println("JWT Validation Failed: Invalid token format");
                return false;
            }

            // Decode and validate header
            JsonNode header = decodeJsonBase64(tokenParts[0]);
            String keyId = header.get("kid").asText();
            String algorithm = header.get("alg").asText();

            if (keyId == null || !"RS256".equals(algorithm)) {
                System.err.println("JWT Validation Failed: Invalid header - keyId: " + keyId + ", alg: " + algorithm);
                return false;
            }

            // Decode and validate payload
            JsonNode payload = decodeJsonBase64(tokenParts[1]);
            
            // Validate issuer
            String issuer = payload.get("iss").asText();
            if (!expectedIssuer.equals(issuer)) {
                System.err.println("JWT Validation Failed: Invalid issuer: " + issuer + ", expected: " + expectedIssuer);
                return false;
            }

            // Validate expiration
            long exp = payload.get("exp").asLong();
            long currentTime = System.currentTimeMillis() / 1000;
            if (exp <= currentTime) {
                System.err.println("JWT Validation Failed: Token expired at: " + new Date(exp * 1000));
                return false;
            }

            // Validate token use
            String tokenUse = payload.has("token_use") ? payload.get("token_use").asText() : null;
            if (!"access".equals(tokenUse)) {
                System.err.println("JWT Validation Failed: Invalid token_use: " + tokenUse);
                return false;
            }

            // Validate client_id if present
            if (payload.has("client_id")) {
                String tokenClientId = payload.get("client_id").asText();
                if (!clientId.equals(tokenClientId)) {
                    System.err.println("JWT Validation Failed: Invalid client_id: " + tokenClientId);
                    return false;
                }
            }

            // Validate signature
            if (!verifySignature(token, keyId)) {
                System.err.println("JWT Validation Failed: Invalid signature");
                return false;
            }

            String username = payload.has("username") ? payload.get("username").asText() : "unknown";
            System.out.println("JWT Validation Success: Token is valid for user: " + username);
            return true;

        } catch (Exception e) {
            System.err.println("JWT Validation Failed: Unexpected error - " + e.getMessage());
            return false;
        }
    }

    /**
     * Verify JWT signature using Cognito public key
     */
    private boolean verifySignature(String token, String keyId) {
        try {
            PublicKey publicKey = getPublicKey(keyId);
            if (publicKey == null) {
                return false;
            }

            String[] parts = token.split("\\.");
            String signedContent = parts[0] + "." + parts[1];
            byte[] signature = Base64.getUrlDecoder().decode(parts[2]);

            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(signedContent.getBytes());

            return verifier.verify(signature);
        } catch (Exception e) {
            System.err.println("Signature verification failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get public key from Cognito JWKS endpoint
     */
    @Cacheable("jwksKeys")
    public PublicKey getPublicKey(String keyId) {
        try {
            // Check cache first
            if (keyCache.containsKey(keyId)) {
                return keyCache.get(keyId);
            }

            // Fetch JWKS from Cognito
            String jwksResponse = webClient.get()
                    .uri(jwksUrl)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            if (jwksResponse == null) {
                System.err.println("Failed to fetch JWKS from Cognito");
                return null;
            }

            // Parse JWKS and find the key
            JsonNode jwks = objectMapper.readTree(jwksResponse);
            JsonNode keys = jwks.get("keys");

            for (JsonNode key : keys) {
                if (keyId.equals(key.get("kid").asText())) {
                    PublicKey publicKey = buildPublicKey(key);
                    keyCache.put(keyId, publicKey);
                    return publicKey;
                }
            }

            System.err.println("Public key not found for key ID: " + keyId);
            return null;

        } catch (Exception e) {
            System.err.println("Error fetching public key: " + e.getMessage());
            return null;
        }
    }

    /**
     * Build RSA public key from JWKS key data
     */
    private PublicKey buildPublicKey(JsonNode key) throws Exception {
        String n = key.get("n").asText();
        String e = key.get("e").asText();

        byte[] nBytes = Base64.getUrlDecoder().decode(n);
        byte[] eBytes = Base64.getUrlDecoder().decode(e);

        BigInteger modulus = new BigInteger(1, nBytes);
        BigInteger exponent = new BigInteger(1, eBytes);

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        
        return factory.generatePublic(spec);
    }

    /**
     * Decode Base64 URL encoded JSON
     */
    private JsonNode decodeJsonBase64(String base64) throws Exception {
        byte[] decoded = Base64.getUrlDecoder().decode(base64);
        return objectMapper.readTree(new String(decoded));
    }

    /**
     * Initialize Cognito URLs
     */
    private void initializeUrls() {
        if (expectedIssuer == null) {
            expectedIssuer = String.format("https://cognito-idp.%s.amazonaws.com/%s", cognitoRegion, userPoolId);
            jwksUrl = expectedIssuer + "/.well-known/jwks.json";
        }
    }

    /**
     * Extract Cognito groups from JWT token
     */
    public List<String> extractCognitoGroupsFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode payloadNode = objectMapper.readTree(payload);

            List<String> groups = new ArrayList<>();
            JsonNode cognitoGroupsNode = payloadNode.get("cognito:groups");
            
            if (cognitoGroupsNode != null && cognitoGroupsNode.isArray()) {
                for (JsonNode groupNode : cognitoGroupsNode) {
                    groups.add(groupNode.asText());
                }
            }
            
            return groups;
        } catch (Exception e) {
            System.err.println("Failed to extract Cognito groups: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Extract username from JWT token
     */
    public String extractUsernameFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode payloadNode = objectMapper.readTree(payload);

            // Try different username fields
            if (payloadNode.has("username")) {
                return payloadNode.get("username").asText();
            } else if (payloadNode.has("email")) {
                return payloadNode.get("email").asText();
            } else if (payloadNode.has("sub")) {
                return payloadNode.get("sub").asText();
            }
            
            return "unknown";
        } catch (Exception e) {
            System.err.println("Failed to extract username: " + e.getMessage());
            return "unknown";
        }
    }

    /**
     * Check if user has admin role
     */
    public boolean isAdmin(String token) {
        List<String> groups = extractCognitoGroupsFromToken(token);
        return groups.contains("ADMIN");
    }

    /**
     * Check if user has any of the specified roles
     */
    public boolean hasAnyRole(String token, String... roles) {
        List<String> userGroups = extractCognitoGroupsFromToken(token);
        for (String role : roles) {
            if (userGroups.contains(role.toUpperCase())) {
                return true;
            }
        }
        return false;
    }
}