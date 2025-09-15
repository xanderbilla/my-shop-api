package com.shop.auth.service;

import com.shop.auth.config.CognitoConfig;
import com.shop.auth.dto.AuthResponse;
import com.shop.auth.dto.SigninRequest;
import com.shop.auth.dto.SignupRequest;
import com.shop.auth.dto.VerifyRequest;
import com.shop.auth.enums.UserRole;
import com.shop.auth.enums.UserStatus;
import com.shop.auth.model.User;
import com.shop.auth.service.UserProfileService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.stream.Collectors;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final CognitoIdentityProviderClient cognitoClient;
    private final CognitoConfig cognitoConfig;
    private final UserProfileService userProfileService;

    public User signup(SignupRequest request) {
        try {
            // Improved username validation
            validateUsername(request.getUsername(), request.getEmail());

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

            User user = createUserWithDefaultStatus(
                    signUpResponse.userSub(), // Set the Cognito UUID as userId
                    request.getUsername(), // Keep the custom username in our system
                    request.getName(),
                    request.getEmail(),
                    false, // User needs to verify email
                    List.of(request.getRole()) // Convert single role to list
            );

            // Create DynamoDB entry for the user profile
            try {
                userProfileService.createUserProfile(user);
            } catch (Exception e) {
                // Log the error but don't fail the signup process
                System.err.println("Failed to create user profile in DynamoDB: " + e.getMessage());
            }

            return user;

        } catch (CognitoIdentityProviderException e) {
            throw new RuntimeException("Failed to create user: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
            throw new RuntimeException("Signup failed: " + e.getMessage());
        }
    }

    public AuthResponse signin(SigninRequest request) {
        try {
            // Find the user's email (actual Cognito username) by their custom username
            String userEmail = findEmailByCustomUsername(request.getUsername());

            // Calculate secret hash using the email (actual Cognito username)
            String secretHash = null;
            if (cognitoConfig.getClientSecret() != null && !cognitoConfig.getClientSecret().isEmpty()) {
                secretHash = calculateSecretHash(userEmail);
            }

            // Build auth parameters using email as username
            Map<String, String> authParameters = new HashMap<>();
            authParameters.put("USERNAME", userEmail);
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

            // Get user attributes using the email
            User user = getUserInfo(userEmail);

            // Update last login timestamp in DynamoDB
            userProfileService.updateLastLogin(user.getUserId());

            // Replace the email with the custom username in the response
            User userWithCustomUsername = createUserBasedOnExisting(user, request.getUsername());

            return new AuthResponse(
                    authResponse.authenticationResult().accessToken(),
                    authResponse.authenticationResult().refreshToken(),
                    userWithCustomUsername);

        } catch (CognitoIdentityProviderException e) {
            throw new RuntimeException("Sign in failed: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
            throw new RuntimeException("Sign in failed: " + e.getMessage());
        }
    }

    public User verify(VerifyRequest request) {
        try {
            // Find the user's email (actual Cognito username) by their custom username
            String userEmail = findEmailByCustomUsername(request.getUsername());

            // Calculate secret hash using the email (actual Cognito username)
            String secretHash = null;
            if (cognitoConfig.getClientSecret() != null && !cognitoConfig.getClientSecret().isEmpty()) {
                secretHash = calculateSecretHash(userEmail);
            }

            ConfirmSignUpRequest.Builder confirmSignUpBuilder = ConfirmSignUpRequest.builder()
                    .clientId(cognitoConfig.getClientId())
                    .username(userEmail)
                    .confirmationCode(request.getVerificationCode());

            if (secretHash != null) {
                confirmSignUpBuilder.secretHash(secretHash);
            }

            cognitoClient.confirmSignUp(confirmSignUpBuilder.build());

            // Get user info and replace email with custom username
            User user = getUserInfo(userEmail);

            // Update verification status in DynamoDB
            userProfileService.updateVerificationStatus(user.getUserId(), true);

            return createUserBasedOnExisting(user, request.getUsername());

        } catch (CognitoIdentityProviderException e) {
            throw new RuntimeException("Verification failed: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
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
            String preferredUsername = null;
            String roleStr = null;
            String userSub = null; // Cognito UUID
            boolean isVerified = getUserResponse.userStatus() == UserStatusType.CONFIRMED;

            for (AttributeType attribute : getUserResponse.userAttributes()) {
                switch (attribute.name()) {
                    case "sub":
                        userSub = attribute.value(); // This is the actual UUID
                        break;
                    case "name":
                        name = attribute.value();
                        break;
                    case "email":
                        email = attribute.value();
                        break;
                    case "preferred_username":
                        preferredUsername = attribute.value();
                        break;
                    case "custom:role":
                        roleStr = attribute.value();
                        break;
                    case "custom:username":
                        if (preferredUsername == null) { // Use custom username if preferred_username is not set
                            preferredUsername = attribute.value();
                        }
                        break;
                    case "role": // Also check for 'role' attribute without custom prefix
                        if (roleStr == null) { // Only use if custom:role wasn't found
                            roleStr = attribute.value();
                        }
                        break;
                }
            }

            // Parse multiple roles from comma-separated string
            List<UserRole> roles = new ArrayList<>();
            if (roleStr != null && !roleStr.trim().isEmpty()) {
                String[] roleArray = roleStr.split(",");
                for (String roleName : roleArray) {
                    try {
                        UserRole role = UserRole.valueOf(roleName.trim());
                        roles.add(role);
                    } catch (IllegalArgumentException e) {
                        // Skip invalid roles
                    }
                }
            }

            // If no valid roles were found, default to USER
            if (roles.isEmpty()) {
                roles.add(UserRole.USER);
            }

            // Generate user-friendly username
            String displayUsername = preferredUsername;
            if (displayUsername == null || displayUsername.trim().isEmpty()) {
                // If no preferred_username, generate from email
                if (email != null) {
                    displayUsername = email.substring(0, email.indexOf('@'));
                } else {
                    displayUsername = "user" + username.substring(0, 8); // Use first 8 chars of UUID
                }
            }

            return createUserWithDefaultStatus(
                    userSub, // Store actual Cognito UUID as userId
                    displayUsername, // Store user-friendly username
                    name,
                    email,
                    isVerified,
                    roles // Use the multiple roles list
            );

        } catch (CognitoIdentityProviderException e) {
            throw new RuntimeException("Failed to get user info: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
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

        } catch (CognitoIdentityProviderException e) {
            throw new RuntimeException("Logout failed: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
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

        } catch (CognitoIdentityProviderException e) {
            throw new RuntimeException("Failed to send reset code: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
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

        } catch (CognitoIdentityProviderException e) {
            throw new RuntimeException("Failed to reset password: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
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

        } catch (CognitoIdentityProviderException e) {
            throw new RuntimeException("Failed to resend verification code: " + e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
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
            return createUserBasedOnExisting(user, customUsername);

        } catch (Exception e) {
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
            return createUserBasedOnExisting(user, customUsername);

        } catch (Exception e) {
            throw new RuntimeException("Failed to get user info: " + e.getMessage());
        }
    }

    public List<UserRole> getUserRoles(String email) {
        try {
            User user = getUserInfo(email);
            return user.getRoles();
        } catch (Exception e) {
            throw new RuntimeException("Failed to get user roles: " + e.getMessage());
        }
    }

    public void updateUserRoles(String email, List<UserRole> newRoles, String requesterIdentifier) {
        try {
            // Check if requester has ADMIN role
            // requesterIdentifier could be either email or Cognito username (UUID)
            User requester;
            if (requesterIdentifier.contains("@")) {
                // It's an email
                requester = getUserInfoByEmail(requesterIdentifier);
            } else {
                // It's a Cognito username (UUID)
                requester = getUserInfo(requesterIdentifier);
            }

            if (requester == null || !requester.hasRole(UserRole.ADMIN)) {
                throw new SecurityException("Only ADMIN users can update roles");
            }

            // Get target user (email is always email in this method)
            User user = getUserInfoByEmail(email);
            if (user == null) {
                throw new RuntimeException("User not found with email: " + email);
            }

            // Update user attributes in Cognito with new roles
            String rolesAsString = newRoles.stream()
                    .map(UserRole::toString)
                    .collect(Collectors.joining(","));

            AdminUpdateUserAttributesRequest updateRequest = AdminUpdateUserAttributesRequest.builder()
                    .userPoolId(cognitoConfig.getUserPoolId())
                    .username(email)
                    .userAttributes(
                            AttributeType.builder()
                                    .name("custom:role")
                                    .value(rolesAsString)
                                    .build())
                    .build();

            cognitoClient.adminUpdateUserAttributes(updateRequest);

        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to update user roles: " + e.getMessage());
        }
    }

    /**
     * Find the actual Cognito username (UUID) by custom username
     */
    /**
     * Find the email (actual Cognito username) by custom username
     */
    public String findEmailByCustomUsername(String customUsername) {
        try {
            // Use ListUsers to find user by custom username attribute
            ListUsersRequest listUsersRequest = ListUsersRequest.builder()
                    .userPoolId(cognitoConfig.getUserPoolId())
                    .build();

            ListUsersResponse response = cognitoClient.listUsers(listUsersRequest);

            // Find the user with matching custom:username attribute and return their email
            for (UserType user : response.users()) {
                String userCustomUsername = null;
                String userEmail = null;

                for (AttributeType attribute : user.attributes()) {
                    if ("custom:username".equals(attribute.name())) {
                        userCustomUsername = attribute.value();
                    } else if ("email".equals(attribute.name())) {
                        userEmail = attribute.value();
                    }
                }

                // If we found the user with matching custom username, return their email
                if (customUsername.equals(userCustomUsername) && userEmail != null) {
                    return userEmail;
                }
            }

            throw new RuntimeException("User not found with username: " + customUsername);

        } catch (CognitoIdentityProviderException e) {
            throw new RuntimeException("User lookup failed: " + e.awsErrorDetails().errorMessage());
        }
    }

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

    public void changePassword(String usernameOrEmail, String currentPassword, String newPassword) {
        try {
            // Determine if it's an email or Cognito username
            String cognitoUsername;
            if (usernameOrEmail.contains("@")) {
                // It's an email
                cognitoUsername = usernameOrEmail;
            } else {
                // It's a Cognito UUID, use it directly
                cognitoUsername = usernameOrEmail;
            }

            // First verify the current password by attempting to authenticate
            AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
                    .userPoolId(cognitoConfig.getUserPoolId())
                    .clientId(cognitoConfig.getClientId())
                    .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                    .authParameters(Map.of(
                            "USERNAME", cognitoUsername,
                            "PASSWORD", currentPassword,
                            "SECRET_HASH", calculateSecretHash(cognitoUsername)))
                    .build();

            // This will throw an exception if current password is wrong
            cognitoClient.adminInitiateAuth(authRequest);

            // If we reach here, current password is correct, proceed with password change
            AdminSetUserPasswordRequest setPasswordRequest = AdminSetUserPasswordRequest.builder()
                    .userPoolId(cognitoConfig.getUserPoolId())
                    .username(cognitoUsername)
                    .password(newPassword)
                    .permanent(true) // Set as permanent password (not temporary)
                    .build();

            cognitoClient.adminSetUserPassword(setPasswordRequest);

        } catch (NotAuthorizedException e) {
            throw new SecurityException("Current password is incorrect");
        } catch (Exception e) {
            throw new RuntimeException("Failed to change password: " + e.getMessage());
        }
    }

    /**
     * Validate username according to business rules:
     * - Cannot be a complete email address (containing @)
     * - Cannot start with a number
     * - Cannot be only numbers
     * - Must be at least 3 characters long
     * - Can contain letters, numbers, underscores, and hyphens
     * - CAN be the same as email prefix (e.g., "xyz" from "xyz@example.com")
     * - Cannot be exactly the same as the full email address
     */
    private void validateUsername(String username, String email) {
        if (username == null || username.trim().isEmpty()) {
            throw new RuntimeException("Username cannot be empty");
        }

        // Remove leading/trailing spaces
        username = username.trim();

        // Cannot be exactly the same as the full email
        if (username.equals(email)) {
            throw new RuntimeException("Username cannot be the same as your email address");
        }

        // Cannot be a complete email (contains @)
        if (username.contains("@")) {
            throw new RuntimeException("Username cannot be an email address");
        }

        // Cannot start with a number
        if (Character.isDigit(username.charAt(0))) {
            throw new RuntimeException("Username cannot start with a number");
        }

        // Cannot be only numbers
        if (username.matches("^\\d+$")) {
            throw new RuntimeException("Username cannot be only numbers");
        }

        // Must be at least 3 characters
        if (username.length() < 3) {
            throw new RuntimeException("Username must be at least 3 characters long");
        }

        // Can only contain letters, numbers, underscores, and hyphens
        if (!username.matches("^[a-zA-Z][a-zA-Z0-9_-]*$")) {
            throw new RuntimeException(
                    "Username can only contain letters, numbers, underscores, and hyphens, and must start with a letter");
        }

        // Username CAN be the same as email prefix - this is explicitly allowed
        // For example: username "xyz" with email "xyz@example.com" is valid
    }

    // ===============================
    // UTILITY METHODS (Reusable)
    // ===============================

    /**
     * Safely gets user status with default fallback
     * 
     * @param user User object that may have null status
     * @return UserStatus, defaulting to ACTIVE if null
     */
    private UserStatus getStatusOrDefault(User user) {
        return user.getStatus() != null ? user.getStatus() : UserStatus.ACTIVE;
    }

    /**
     * Creates a User with default ACTIVE status
     * 
     * @param userId     User ID
     * @param username   Username
     * @param name       Display name
     * @param email      Email address
     * @param isVerified Verification status
     * @param roles      User roles
     * @return User object with default ACTIVE status
     */
    private User createUserWithDefaultStatus(String userId, String username, String name,
            String email, boolean isVerified, List<UserRole> roles) {
        return User.builder()
                .userId(userId)
                .username(username)
                .name(name)
                .email(email)
                .isVerified(isVerified)
                .roles(roles)
                .status(UserStatus.ACTIVE)
                .build();
    }

    /**
     * Creates a User based on existing User but with potentially updated fields
     * 
     * @param existingUser Existing user to copy from
     * @param username     New username (or null to keep existing)
     * @return User object with preserved status or default ACTIVE
     */
    private User createUserBasedOnExisting(User existingUser, String username) {
        return User.builder()
                .userId(existingUser.getUserId())
                .username(username != null ? username : existingUser.getUsername())
                .name(existingUser.getName())
                .email(existingUser.getEmail())
                .isVerified(existingUser.isVerified())
                .roles(existingUser.getRoles())
                .status(getStatusOrDefault(existingUser))
                .build();
    }
}