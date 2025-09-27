package com.shop.carousel.service;

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
import java.util.concurrent.ConcurrentHashMap;

@Service
public class JwtTokenService {

    private final ObjectMapper objectMapper;
    private final WebClient webClient;
    private final Map<String, PublicKey> keyCache = new ConcurrentHashMap<>();

    @Value("${aws.cognito.region}")
    private String cognitoRegion;

    @Value("${aws.cognito.user-pool-id}")
    private String userPoolId;

    public JwtTokenService() {
        this.objectMapper = new ObjectMapper();
        this.webClient = WebClient.builder().build();
    }

    /**
     * Validates JWT token signature, expiration, and issuer
     */
    public boolean isValidToken(String token) {
        try {
            String[] chunks = token.split("\\.");
            if (chunks.length != 3) {
                return false;
            }

            // Decode header and payload
            String header = new String(Base64.getUrlDecoder().decode(chunks[0]));
            String payload = new String(Base64.getUrlDecoder().decode(chunks[1]));

            JsonNode headerNode = objectMapper.readTree(header);
            JsonNode payloadNode = objectMapper.readTree(payload);

            // Validate expiration
            long exp = payloadNode.get("exp").asLong();
            if (System.currentTimeMillis() / 1000 >= exp) {
                return false;
            }

            // Validate issuer
            String expectedIssuer = "https://cognito-idp." + cognitoRegion + ".amazonaws.com/" + userPoolId;
            String actualIssuer = payloadNode.get("iss").asText();
            if (!expectedIssuer.equals(actualIssuer)) {
                return false;
            }

            // Validate signature
            String kid = headerNode.get("kid").asText();
            PublicKey publicKey = getPublicKey(kid);
            if (publicKey == null) {
                return false;
            }

            return verifySignature(chunks[0] + "." + chunks[1], chunks[2], publicKey);
        } catch (Exception e) {
            System.err.println("Token validation failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Extracts username (email) from JWT token
     */
    public String extractUsernameFromToken(String token) {
        try {
            String[] chunks = token.split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(chunks[1]));
            JsonNode payloadNode = objectMapper.readTree(payload);
            return payloadNode.get("username").asText();
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract username from token", e);
        }
    }

    /**
     * Extracts Cognito groups from JWT token
     */
    public List<String> extractCognitoGroupsFromToken(String token) {
        try {
            String[] chunks = token.split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(chunks[1]));
            JsonNode payloadNode = objectMapper.readTree(payload);
            
            JsonNode groupsNode = payloadNode.get("cognito:groups");
            List<String> groups = new ArrayList<>();
            
            if (groupsNode != null && groupsNode.isArray()) {
                for (JsonNode groupNode : groupsNode) {
                    groups.add(groupNode.asText());
                }
            }
            
            return groups;
        } catch (Exception e) {
            System.err.println("Failed to extract groups from token: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Check if user has admin role
     */
    public boolean isAdmin(String token) {
        List<String> groups = extractCognitoGroupsFromToken(token);
        return groups.contains("ADMIN");
    }

    @Cacheable("jwks")
    private PublicKey getPublicKey(String kid) {
        if (keyCache.containsKey(kid)) {
            return keyCache.get(kid);
        }

        try {
            String jwksUrl = "https://cognito-idp." + cognitoRegion + ".amazonaws.com/" + userPoolId + "/.well-known/jwks.json";
            String response = webClient.get()
                    .uri(jwksUrl)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            JsonNode jwks = objectMapper.readTree(response);
            JsonNode keys = jwks.get("keys");

            for (JsonNode key : keys) {
                if (kid.equals(key.get("kid").asText())) {
                    PublicKey publicKey = buildPublicKey(key);
                    keyCache.put(kid, publicKey);
                    return publicKey;
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to get public key: " + e.getMessage());
        }
        return null;
    }

    private PublicKey buildPublicKey(JsonNode key) throws Exception {
        String nStr = key.get("n").asText();
        String eStr = key.get("e").asText();

        byte[] nBytes = Base64.getUrlDecoder().decode(nStr);
        byte[] eBytes = Base64.getUrlDecoder().decode(eStr);

        BigInteger n = new BigInteger(1, nBytes);
        BigInteger e = new BigInteger(1, eBytes);

        RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    private boolean verifySignature(String data, String signature, PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data.getBytes());
            return sig.verify(Base64.getUrlDecoder().decode(signature));
        } catch (Exception e) {
            return false;
        }
    }
}