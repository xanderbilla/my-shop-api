package com.shop.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "aws.cognito")
public class CognitoConfig {

    private String region;
    private String userPoolId;
    private String clientId;
    private String clientSecret;

    // Getters with environment variable fallback
    public String getRegion() {
        return region != null ? region : System.getenv("AWS_COGNITO_REGION");
    }

    public String getUserPoolId() {
        return userPoolId != null ? userPoolId : System.getenv("AWS_COGNITO_USER_POOL_ID");
    }

    public String getClientId() {
        return clientId != null ? clientId : System.getenv("AWS_COGNITO_CLIENT_ID");
    }

    public String getClientSecret() {
        return clientSecret != null ? clientSecret : System.getenv("AWS_COGNITO_CLIENT_SECRET");
    }
}