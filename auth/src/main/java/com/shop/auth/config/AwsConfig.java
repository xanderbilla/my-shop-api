package com.shop.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;

@Configuration
public class AwsConfig {

    @Autowired
    private CognitoConfig cognitoConfig;

    @Bean
    public CognitoIdentityProviderClient cognitoIdentityProviderClient() {
        String region = cognitoConfig.getRegion();
        if (region == null || region.isEmpty()) {
            region = "us-east-1"; // Default region
        }

        return CognitoIdentityProviderClient.builder()
                .region(Region.of(region))
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }
}