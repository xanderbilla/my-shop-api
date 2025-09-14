package com.shop.auth.service;

import com.shop.auth.config.CognitoConfig;
import com.shop.auth.dto.AuthResponse;
import com.shop.auth.dto.SigninRequest;
import com.shop.auth.dto.SignupRequest;
import com.shop.auth.dto.VerifyRequest;
import com.shop.auth.enums.UserRole;
import com.shop.auth.model.User;
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

            return User.builder()
                    .username(request.getUsername()) // Keep the custom username in our system
                    .name(request.getName())
                    .email(request.getEmail())
                    .isVerified(false) // User needs to verify email
                    .roles(List.of(request.getRole())) // Convert single role to list
                    .build();

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

            // Replace the email with the custom username in the response
            User userWithCustomUsername = User.builder()
                    .username(request.getUsername()) // Use custom username instead of email
                    .name(user.getName())
                    .email(user.getEmail())
                    .isVerified(user.isVerified())
                    .roles(user.getRoles())
                    .build();

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
            return User.builder()
                    .username(request.getUsername()) // Use custom username instead of email
                    .name(user.getName())
                    .email(user.getEmail())
                    .isVerified(user.isVerified())
                    .roles(user.getRoles())
                    .build();

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
            boolean isVerified = getUserResponse.userStatus() == UserStatusType.CONFIRMED;

            for (AttributeType attribute : getUserResponse.userAttributes()) {
                switch (attribute.name()) {
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

            return User.builder()
                    .userId(username) // Store Cognito UUID as userId
                    .username(displayUsername) // Store user-friendly username
                    .name(name)
                    .email(email)
                    .isVerified(isVerified)
                    .roles(roles) // Use the multiple roles list
                    .build();

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
            return User.builder()
                    .username(customUsername) // Use custom username instead of UUID
                    .name(user.getName())
                    .email(user.getEmail())
                    .isVerified(user.isVerified())
                    .roles(user.getRoles())
                    .build();

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
            return User.builder()
                    .username(customUsername) // Use custom username instead of email/UUID
                    .name(user.getName())
                    .email(user.getEmail())
                    .isVerified(user.isVerified())
                    .roles(user.getRoles())
                    .build();

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
}