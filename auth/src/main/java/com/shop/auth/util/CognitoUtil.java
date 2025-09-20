package com.shop.auth.util;

import com.shop.auth.config.CognitoConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Utility class for AWS Cognito operations
 */
@Component
@RequiredArgsConstructor
public class CognitoUtil {

    private final CognitoConfig cognitoConfig;

    /**
     * Calculate secret hash for AWS Cognito operations
     * 
     * @param username The username (usually email)
     * @return The calculated secret hash or null if no client secret is configured
     */
    public String calculateSecretHash(String username) {
        if (cognitoConfig.getClientSecret() == null || cognitoConfig.getClientSecret().isEmpty()) {
            return null;
        }

        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(
                    cognitoConfig.getClientSecret().getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256");
            mac.init(secretKeySpec);

            String message = username + cognitoConfig.getClientId();
            byte[] hmac = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(hmac);
        } catch (Exception e) {
            throw new RuntimeException("Failed to calculate secret hash", e);
        }
    }

    /**
     * Check if client secret is configured
     * 
     * @return true if client secret is configured, false otherwise
     */
    public boolean isClientSecretConfigured() {
        return cognitoConfig.getClientSecret() != null && !cognitoConfig.getClientSecret().isEmpty();
    }
}