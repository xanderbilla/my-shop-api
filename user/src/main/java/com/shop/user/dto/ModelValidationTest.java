package com.shop.user.dto;

import com.shop.user.enums.UserRole;
import java.util.Arrays;

/**
 * Test DTO to validate model usage instead of Map
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-21
 */
public class ModelValidationTest {

    public static void main(String[] args) {
        // Test UserCreationRequest
        UserCreationRequest request = new UserCreationRequest();
        request.setEmail("test@example.com");
        request.setName("Test User");
        request.setRoles(Arrays.asList(UserRole.USER));

        System.out.println("UserCreationRequest: " + request);

        // Test UserCreationResponse
        UserCreationResponse response = new UserCreationResponse();
        response.setUserId("test-id");
        response.setCognitoUsername("test-username");
        response.setEmail("test@example.com");
        response.setTemporaryPassword("temp-pass");
        response.setRoles(Arrays.asList(UserRole.USER));
        response.setStatus("created");

        System.out.println("UserCreationResponse: " + response);

        // Test CognitoUserCreationResponse
        CognitoUserCreationResponse cognitoResponse = new CognitoUserCreationResponse();
        cognitoResponse.setUsername("test-username");
        cognitoResponse.setTemporaryPassword("temp-pass");
        cognitoResponse.setEmail("test@example.com");
        cognitoResponse.setGroup(UserRole.USER);

        System.out.println("CognitoUserCreationResponse: " + cognitoResponse);

        // Test HealthResponse
        HealthResponse healthResponse = new HealthResponse("user-service", "UP");
        System.out.println("HealthResponse: " + healthResponse);

        System.out.println("All DTO models are working correctly!");
    }
}