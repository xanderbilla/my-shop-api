package com.shop.auth.service;

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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class JwtTokenService {

    // In-memory blacklist for tokens (in production, use Redis or database)
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();
    private final ObjectMapper objectMapper;
    private final WebClient webClient;
    private final Map<String, PublicKey> keyCache = new ConcurrentHashMap<>();

    @Value("${aws.cognito.region}")
    private String cognitoRegion;

    @Value("${aws.cognito.userPoolId}")
    private String userPoolId;

    private String expectedIssuer;
    private String jwksUrl;

    public JwtTokenService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.webClient = WebClient.builder().build();
    }

    /**
     * Comprehensive JWT token validation with signature verification
     */
    public boolean isValidToken(String token) {
        try {
            if (token == null || token.trim().isEmpty()) {
                return false;
            }

            // Check if token is blacklisted first
            if (isTokenBlacklisted(token)) {
                return false;
            }

            // Initialize URLs if needed
            initializeUrls();

            // Validate JWT structure
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return false;
            }

            // Decode header and payload
            JsonNode header = decodeJsonBase64(parts[0]);
            JsonNode payload = decodeJsonBase64(parts[1]);

            // Validate token expiry
            if (payload.has("exp")) {
                long exp = payload.get("exp").asLong();
                if (System.currentTimeMillis() / 1000 >= exp) {
                    System.err.println("Token has expired");
                    return false;
                }
            }

            // Validate issuer
            if (payload.has("iss")) {
                String issuer = payload.get("iss").asText();
                if (!expectedIssuer.equals(issuer)) {
                    System.err.println("Invalid issuer: " + issuer);
                    return false;
                }
            }

            // Validate token use (should be 'access' for API access)
            if (payload.has("token_use")) {
                String tokenUse = payload.get("token_use").asText();
                if (!"access".equals(tokenUse)) {
                    System.err.println("Invalid token use: " + tokenUse);
                    return false;
                }
            }

            // Verify signature using Cognito JWKS
            if (!verifySignature(token, header)) {
                System.err.println("Signature verification failed");
                return false;
            }

            return true;
        } catch (Exception e) {
            System.err.println("Token validation error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Verify JWT signature using Cognito JWKS
     */
    private boolean verifySignature(String token, JsonNode header) {
        try {
            String kid = header.get("kid").asText();
            String alg = header.get("alg").asText();

            if (!"RS256".equals(alg)) {
                System.err.println("Unsupported algorithm: " + alg);
                return false;
            }

            PublicKey publicKey = getPublicKey(kid);
            if (publicKey == null) {
                System.err.println("Unable to get public key for kid: " + kid);
                return false;
            }

            String[] parts = token.split("\\.");
            String headerAndPayload = parts[0] + "." + parts[1];
            byte[] signature = Base64.getUrlDecoder().decode(parts[2]);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(headerAndPayload.getBytes());

            return sig.verify(signature);
        } catch (Exception e) {
            System.err.println("Signature verification error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get public key from Cognito JWKS with caching
     */
    @Cacheable("jwks-keys")
    private PublicKey getPublicKey(String kid) {
        try {
            if (keyCache.containsKey(kid)) {
                return keyCache.get(kid);
            }

            // Fetch JWKS from Cognito
            String jwksResponse = webClient.get()
                    .uri(jwksUrl)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            JsonNode jwks = objectMapper.readTree(jwksResponse);
            JsonNode keys = jwks.get("keys");

            for (JsonNode key : keys) {
                if (kid.equals(key.get("kid").asText())) {
                    String n = key.get("n").asText();
                    String e = key.get("e").asText();

                    byte[] nBytes = Base64.getUrlDecoder().decode(n);
                    byte[] eBytes = Base64.getUrlDecoder().decode(e);

                    BigInteger modulus = new BigInteger(1, nBytes);
                    BigInteger exponent = new BigInteger(1, eBytes);

                    RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
                    KeyFactory factory = KeyFactory.getInstance("RSA");
                    PublicKey publicKey = factory.generatePublic(spec);

                    keyCache.put(kid, publicKey);
                    return publicKey;
                }
            }

            return null;
        } catch (Exception e) {
            System.err.println("Error fetching public key: " + e.getMessage());
            return null;
        }
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
     * Blacklist a token (for logout functionality)
     */
    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
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
     * Extract custom username from JWT token payload
     */
    public String extractCustomUsernameFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode payloadNode = objectMapper.readTree(payload);

            if (payloadNode.has("custom:username")) {
                return payloadNode.get("custom:username").asText();
            }

            return "unknown";
        } catch (Exception e) {
            System.err.println("Failed to extract custom username: " + e.getMessage());
            return "unknown";
        }
    }

    /**
     * Extract email from JWT token payload
     */
    public String extractEmailFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode payloadNode = objectMapper.readTree(payload);

            // Try email field first
            if (payloadNode.has("email")) {
                return payloadNode.get("email").asText();
            } else if (payloadNode.has("username")) {
                return payloadNode.get("username").asText();
            }

            return "unknown";
        } catch (Exception e) {
            System.err.println("Failed to extract email: " + e.getMessage());
            return "unknown";
        }
    }

    /**
     * Extract Cognito username (UUID) from JWT token
     */
    public String extractCognitoUsernameFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode payloadNode = objectMapper.readTree(payload);

            if (payloadNode.has("username")) {
                return payloadNode.get("username").asText();
            } else if (payloadNode.has("sub")) {
                return payloadNode.get("sub").asText();
            }

            return "unknown";
        } catch (Exception e) {
            System.err.println("Failed to extract Cognito username: " + e.getMessage());
            return "unknown";
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
     * Check if user has a specific group/role from cognito:groups claim
     */
    public boolean hasGroup(String token, String groupName) {
        List<String> groups = extractCognitoGroupsFromToken(token);
        return groups.contains(groupName);
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