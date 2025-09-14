package com.shop.auth.service;

import com.shop.auth.config.CognitoConfig;
import com.shop.auth.dto.AuthResponse;
import com.shop.auth.dto.SigninRequest;
import com.shop.auth.dto.SignupRequest;
import com.shop.auth.dto.VerifyRequest;
import com.shop.auth.enums.UserRole;
import com.shop.auth.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final CognitoIdentityProviderClient cognitoClient;
    private final CognitoConfig cognitoConfig;

    // Constructor for dependency injection
    public AuthService(CognitoIdentityProviderClient cognitoClient, CognitoConfig cognitoConfig) {
        this.cognitoClient = cognitoClient;
        this.cognitoConfig = cognitoConfig;
    }

    public User signup(SignupRequest request) {
        try {
            // Validate that username is not the same as email or part of email
            String emailPrefix = request.getEmail().split("@")[0];
            if (request.getUsername().equals(request.getEmail()) ||
                    request.getUsername().equals(emailPrefix) ||
                    request.getEmail().contains(request.getUsername())) {
                throw new RuntimeException("Username cannot be the same as email or part of email");
            }

            // Create user attributes
            Map<String, String> userAttributes = new HashMap<>();
            userAttributes.put("email", request.getEmail());
            userAttributes.put("name", request.getName());
            userAttributes.put("custom:role", request.getRole().name());
            userAttributes.put("custom:username", request.getUsername()); // Store custom username as attribute

            // Calculate secret hash if client secret is provided
            String secretHash = null;
            if (cognitoConfig.getClientSecret() != null && !cognitoConfig.getClientSecret().isEmpty()) {
                secretHash = calculateSecretHash(request.getEmail()); // Use email for secret hash since Cognito uses
                                                                      // email as username
            }

            // Build the signup request using email as username (as per Cognito
            // configuration)
            SignUpRequest.Builder signUpBuilder = SignUpRequest.builder()
                    .clientId(cognitoConfig.getClientId())
                    .username(request.getEmail()) // Use email as Cognito username
                    .password(request.getPassword())
                    .userAttributes(
                            userAttributes.entrySet().stream()
                                    .map(entry -> AttributeType.builder()
                                            .name(entry.getKey())
                                            .value(entry.getValue())
                                            .build())
                                    .toArray(AttributeType[]::new));

            if (secretHash != null) {
                signUpBuilder.secretHash(secretHash);
            }

            SignUpResponse signUpResponse = cognitoClient.signUp(signUpBuilder.build());
            log.info("User signup initiated for email: {}, username: {}, UserSub: {}",
                    request.getEmail(), request.getUsername(), signUpResponse.userSub());

            return User.builder()
                    .username(request.getUsername()) // Keep the custom username in our system
                    .name(request.getName())
                    .email(request.getEmail())
                    .isVerified(false) // User needs to verify email
                    .role(request.getRole())
                    .build();

        } catch (CognitoIdentityProviderException e) {
            log.error("Error creating user: {}", e.getMessage());
            throw new RuntimeException("Failed to create user: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
            log.error("Unexpected error during signup: {}", e.getMessage());
            throw new RuntimeException("Signup failed: " + e.getMessage());
        }
    }

    public AuthResponse signin(SigninRequest request) {
        try {
            // Find the actual Cognito username (UUID) based on custom username
            String actualCognitoUsername = findCognitoUsernameByCustomUsername(request.getUsername());

            // Calculate secret hash using the actual Cognito username
            String secretHash = null;
            if (cognitoConfig.getClientSecret() != null && !cognitoConfig.getClientSecret().isEmpty()) {
                secretHash = calculateSecretHash(actualCognitoUsername);
            }

            // Build auth parameters
            Map<String, String> authParameters = new HashMap<>();
            authParameters.put("USERNAME", actualCognitoUsername);
            authParameters.put("PASSWORD", request.getPassword());
            if (secretHash != null) {
                authParameters.put("SECRET_HASH", secretHash);
            }

            AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
                    .userPoolId(cognitoConfig.getUserPoolId())
                    .clientId(cognitoConfig.getClientId())
                    .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                    .authParameters(authParameters)
                    .build();

            AdminInitiateAuthResponse authResponse = cognitoClient.adminInitiateAuth(authRequest);

            if (authResponse.challengeName() != null) {
                throw new RuntimeException("Authentication challenge required: " + authResponse.challengeName());
            }

            // Get user attributes using the actual Cognito username
            User user = getUserInfo(actualCognitoUsername);

            // Replace the Cognito UUID with the custom username in the response
            User userWithCustomUsername = User.builder()
                    .username(request.getUsername()) // Use custom username instead of UUID
                    .name(user.getName())
                    .email(user.getEmail())
                    .isVerified(user.isVerified())
                    .role(user.getRole())
                    .build();

            log.info("User signed in successfully: {} (Cognito ID: {})", request.getUsername(), actualCognitoUsername);

            return new AuthResponse(
                    authResponse.authenticationResult().accessToken(),
                    authResponse.authenticationResult().refreshToken(),
                    userWithCustomUsername);

        } catch (CognitoIdentityProviderException e) {
            log.error("Error signing in user: {}", e.getMessage());
            throw new RuntimeException("Sign in failed: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
            log.error("Unexpected error during signin: {}", e.getMessage());
            throw new RuntimeException("Sign in failed: " + e.getMessage());
        }
    }

    public User verify(VerifyRequest request) {
        try {
            // Find the actual Cognito username (UUID) based on custom username
            String actualCognitoUsername = findCognitoUsernameByCustomUsername(request.getUsername());

            // Calculate secret hash using the actual Cognito username
            String secretHash = null;
            if (cognitoConfig.getClientSecret() != null && !cognitoConfig.getClientSecret().isEmpty()) {
                secretHash = calculateSecretHash(actualCognitoUsername);
            }

            ConfirmSignUpRequest.Builder confirmSignUpBuilder = ConfirmSignUpRequest.builder()
                    .clientId(cognitoConfig.getClientId())
                    .username(actualCognitoUsername)
                    .confirmationCode(request.getVerificationCode());

            if (secretHash != null) {
                confirmSignUpBuilder.secretHash(secretHash);
            }

            cognitoClient.confirmSignUp(confirmSignUpBuilder.build());

            log.info("User verified successfully: {} (Cognito ID: {})", request.getUsername(), actualCognitoUsername);

            // Get user info and replace UUID with custom username
            User user = getUserInfo(actualCognitoUsername);
            return User.builder()
                    .username(request.getUsername()) // Use custom username instead of UUID
                    .name(user.getName())
                    .email(user.getEmail())
                    .isVerified(user.isVerified())
                    .role(user.getRole())
                    .build();

        } catch (CognitoIdentityProviderException e) {
            log.error("Error verifying user: {}", e.getMessage());
            throw new RuntimeException("Verification failed: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
            log.error("Unexpected error during verification: {}", e.getMessage());
            throw new RuntimeException("Verification failed: " + e.getMessage());
        }
    }

    public User getUserInfo(String username) {
        try {
            AdminGetUserRequest getUserRequest = AdminGetUserRequest.builder()
                    .userPoolId(cognitoConfig.getUserPoolId())
                    .username(username)
                    .build();

            AdminGetUserResponse getUserResponse = cognitoClient.adminGetUser(getUserRequest);

            // Extract user attributes
            String name = null;
            String email = null;
            String roleStr = null;
            boolean isVerified = getUserResponse.userStatus() == UserStatusType.CONFIRMED;

            for (AttributeType attribute : getUserResponse.userAttributes()) {
                switch (attribute.name()) {
                    case "name":
                        name = attribute.value();
                        break;
                    case "email":
                        email = attribute.value();
                        break;
                    case "custom:role":
                        roleStr = attribute.value();
                        break;
                }
            }

            UserRole role = UserRole.USER; // Default
            if (roleStr != null) {
                try {
                    role = UserRole.valueOf(roleStr);
                } catch (IllegalArgumentException e) {
                    log.warn("Invalid role value: {}, defaulting to USER", roleStr);
                }
            }

            return User.builder()
                    .username(username)
                    .name(name)
                    .email(email)
                    .isVerified(isVerified)
                    .role(role)
                    .build();

        } catch (CognitoIdentityProviderException e) {
            log.error("Error getting user info: {}", e.getMessage());
            throw new RuntimeException("Failed to get user info: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
            log.error("Unexpected error getting user info: {}", e.getMessage());
            throw new RuntimeException("Failed to get user info: " + e.getMessage());
        }
    }

    public void logout(String accessToken) {
        try {
            // Global sign out the user from all devices
            GlobalSignOutRequest signOutRequest = GlobalSignOutRequest.builder()
                    .accessToken(accessToken)
                    .build();

            cognitoClient.globalSignOut(signOutRequest);
            log.info("User logged out successfully");

        } catch (CognitoIdentityProviderException e) {
            log.error("Error logging out user: {}", e.getMessage());
            throw new RuntimeException("Logout failed: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
            log.error("Unexpected error during logout: {}", e.getMessage());
            throw new RuntimeException("Logout failed: " + e.getMessage());
        }
    }

    public void forgotPassword(String email) {
        try {
            // Calculate secret hash if client secret is provided
            String secretHash = null;
            if (cognitoConfig.getClientSecret() != null && !cognitoConfig.getClientSecret().isEmpty()) {
                secretHash = calculateSecretHash(email);
            }

            ForgotPasswordRequest.Builder forgotPasswordBuilder = ForgotPasswordRequest.builder()
                    .clientId(cognitoConfig.getClientId())
                    .username(email); // Use email as username

            if (secretHash != null) {
                forgotPasswordBuilder.secretHash(secretHash);
            }

            cognitoClient.forgotPassword(forgotPasswordBuilder.build());
            log.info("Password reset code sent to email: {}", email);

        } catch (CognitoIdentityProviderException e) {
            log.error("Error sending password reset code: {}", e.getMessage());
            throw new RuntimeException("Failed to send reset code: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
            log.error("Unexpected error during forgot password: {}", e.getMessage());
            throw new RuntimeException("Failed to send reset code: " + e.getMessage());
        }
    }

    public void resetPassword(String email, String verificationCode, String newPassword) {
        try {
            // Calculate secret hash if client secret is provided
            String secretHash = null;
            if (cognitoConfig.getClientSecret() != null && !cognitoConfig.getClientSecret().isEmpty()) {
                secretHash = calculateSecretHash(email);
            }

            ConfirmForgotPasswordRequest.Builder confirmForgotPasswordBuilder = ConfirmForgotPasswordRequest.builder()
                    .clientId(cognitoConfig.getClientId())
                    .username(email) // Use email as username
                    .confirmationCode(verificationCode)
                    .password(newPassword);

            if (secretHash != null) {
                confirmForgotPasswordBuilder.secretHash(secretHash);
            }

            cognitoClient.confirmForgotPassword(confirmForgotPasswordBuilder.build());
            log.info("Password reset successfully for email: {}", email);

        } catch (CognitoIdentityProviderException e) {
            log.error("Error resetting password: {}", e.getMessage());
            throw new RuntimeException("Failed to reset password: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
            log.error("Unexpected error during password reset: {}", e.getMessage());
            throw new RuntimeException("Failed to reset password: " + e.getMessage());
        }
    }

    public void resendVerificationCode(String email) {
        try {
            // Calculate secret hash if client secret is provided
            String secretHash = null;
            if (cognitoConfig.getClientSecret() != null && !cognitoConfig.getClientSecret().isEmpty()) {
                secretHash = calculateSecretHash(email);
            }

            ResendConfirmationCodeRequest.Builder resendCodeBuilder = ResendConfirmationCodeRequest.builder()
                    .clientId(cognitoConfig.getClientId())
                    .username(email); // Use email as username

            if (secretHash != null) {
                resendCodeBuilder.secretHash(secretHash);
            }

            cognitoClient.resendConfirmationCode(resendCodeBuilder.build());
            log.info("Verification code resent to email: {}", email);

        } catch (CognitoIdentityProviderException e) {
            log.error("Error resending verification code: {}", e.getMessage());
            throw new RuntimeException("Failed to resend verification code: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
            log.error("Unexpected error during resend verification: {}", e.getMessage());
            throw new RuntimeException("Failed to resend verification code: " + e.getMessage());
        }
    }

    public User getUserInfoByCustomUsername(String customUsername) {
        try {
            // Find the actual Cognito username first
            String actualCognitoUsername = findCognitoUsernameByCustomUsername(customUsername);

            // Get user info using the actual Cognito username
            User user = getUserInfo(actualCognitoUsername);

            // Replace the Cognito UUID with the custom username in the response
            return User.builder()
                    .username(customUsername) // Use custom username instead of UUID
                    .name(user.getName())
                    .email(user.getEmail())
                    .isVerified(user.isVerified())
                    .role(user.getRole())
                    .build();

        } catch (Exception e) {
            log.error("Error getting user info by custom username: {}", e.getMessage());
            throw new RuntimeException("Failed to get user info: " + e.getMessage());
        }
    }

    public User getUserInfoByEmail(String email) {
        try {
            // Find the actual Cognito username (which is the email) and get user info
            User user = getUserInfo(email);

            // Find the custom username for this email
            String customUsername = findCustomUsernameByEmail(email);

            // Replace the Cognito UUID/email with the custom username in the response
            return User.builder()
                    .username(customUsername) // Use custom username instead of email/UUID
                    .name(user.getName())
                    .email(user.getEmail())
                    .isVerified(user.isVerified())
                    .role(user.getRole())
                    .build();

        } catch (Exception e) {
            log.error("Error getting user info by email: {}", e.getMessage());
            throw new RuntimeException("Failed to get user info: " + e.getMessage());
        }
    }

    /**
     * Find the actual Cognito username (UUID) by custom username
     */
    private String findCognitoUsernameByCustomUsername(String customUsername) {
        try {
            // Use ListUsers to find user by custom username attribute
            ListUsersRequest listUsersRequest = ListUsersRequest.builder()
                    .userPoolId(cognitoConfig.getUserPoolId())
                    .build();

            ListUsersResponse response = cognitoClient.listUsers(listUsersRequest);

            // Find the user with matching custom:username attribute
            for (UserType user : response.users()) {
                for (AttributeType attribute : user.attributes()) {
                    if ("custom:username".equals(attribute.name()) &&
                            customUsername.equals(attribute.value())) {
                        return user.username();
                    }
                }
            }

            throw new RuntimeException("User not found with username: " + customUsername);

        } catch (CognitoIdentityProviderException e) {
            log.error("Error finding user by custom username: {}", e.getMessage());
            throw new RuntimeException("User lookup failed: " + e.awsErrorDetails().errorMessage());
        }
    }

    /**
     * Find the custom username by email
     */
    private String findCustomUsernameByEmail(String email) {
        try {
            // Use ListUsers to find user by email and get custom username attribute
            ListUsersRequest listUsersRequest = ListUsersRequest.builder()
                    .userPoolId(cognitoConfig.getUserPoolId())
                    .build();

            ListUsersResponse response = cognitoClient.listUsers(listUsersRequest);

            // Find the user with matching email and extract custom username
            for (UserType user : response.users()) {
                // Check if this user has the matching email
                String userEmail = null;
                String customUsername = null;

                for (AttributeType attribute : user.attributes()) {
                    if ("email".equals(attribute.name())) {
                        userEmail = attribute.value();
                    } else if ("custom:username".equals(attribute.name())) {
                        customUsername = attribute.value();
                    }
                }

                // If we found a user with matching email, return their custom username
                if (email.equals(userEmail) && customUsername != null) {
                    return customUsername;
                }
            }

            throw new RuntimeException("User not found with email: " + email);

        } catch (CognitoIdentityProviderException e) {
            log.error("Error finding custom username by email: {}", e.getMessage());
            throw new RuntimeException("User lookup failed: " + e.awsErrorDetails().errorMessage());
        }
    }

    private String calculateSecretHash(String username) {
        try {
            String message = username + cognitoConfig.getClientId();
            Mac sha256Hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(
                    cognitoConfig.getClientSecret().getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256");
            sha256Hmac.init(secretKey);
            byte[] hash = sha256Hmac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error calculating secret hash", e);
        }
    }
}