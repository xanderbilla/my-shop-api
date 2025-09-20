package com.shop.admin.service;

import com.shop.admin.model.User;
import com.shop.admin.model.User.Address;
import com.shop.admin.enums.UserRole;
import com.shop.admin.enums.UserStatus;
import com.shop.admin.enums.FraudRisk;
import com.shop.admin.repository.UserProfileRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Service class for User management operations
 * 
 * Provides business logic for user administration including:
 * - User retrieval and updates
 * - Soft deletion with audit fields
 * - Address management
 * - Role updates with Cognito group synchronization
 * - User verification management
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-20
 * @created 2025-09-20
 * @lastModified 2025-09-20
 * 
 * @reference AWS Cognito Identity Provider
 * @reference DynamoDB User Profile Repository
 */
@Service
public class UserService {

    private final UserProfileRepository userProfileRepository;
    private final CognitoIdentityProviderClient cognitoClient;
    private final String userPoolId;

    public UserService(UserProfileRepository userProfileRepository,
            CognitoIdentityProviderClient cognitoClient,
            @Value("${aws.cognito.user-pool-id}") String userPoolId) {
        this.userProfileRepository = userProfileRepository;
        this.cognitoClient = cognitoClient;
        this.userPoolId = userPoolId;
    }

    /**
     * Retrieves all users from the system
     * 
     * @return List of all users
     */
    public List<User> getAllUsers() {
        return userProfileRepository.getAllUsers();
    }

    /**
     * Retrieves a limited number of users
     * 
     * @param limit Maximum number of users to retrieve
     * @return List of users up to the specified limit
     */
    public List<User> getAllUsers(int limit) {
        return userProfileRepository.getAllUsers(limit);
    }

    /**
     * Retrieves a single user by their UUID
     * 
     * @param userId The unique identifier of the user
     * @return Optional containing the user if found
     * @throws IllegalArgumentException if userId is null or empty
     */
    public Optional<User> getUserById(String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            throw new IllegalArgumentException("User ID cannot be null or empty");
        }
        return userProfileRepository.getUserById(userId);
    }

    /**
     * Performs soft deletion of a user by setting delete flags and timestamps
     * 
     * @param userId    The unique identifier of the user to delete
     * @param deletedBy The identifier of the admin performing the deletion
     * @return The updated user object with deletion information
     * @throws RuntimeException if user not found or already deleted
     */
    public User softDeleteUser(String userId, String deletedBy) {
        User user = getUserById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        if (user.getDeleteStatus() != null && user.getDeleteStatus().getIsDeleted()) {
            throw new RuntimeException("User is already deleted");
        }

        // Update delete status
        User.DeleteStatus deleteStatus = User.DeleteStatus.builder()
                .isDeleted(true)
                .deletedAt(Instant.now())
                .restoresCount(user.getDeleteStatus() != null ? user.getDeleteStatus().getRestoresCount() : 0)
                .restoreAt(null)
                .build();

        user.setDeleteStatus(deleteStatus);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(deletedBy);
        user.setIsActive(false);

        // Disable user in Cognito to prevent login
        disableCognitoUser(user.getEmail());

        return userProfileRepository.updateUser(user);
    }

    /**
     * Changes the default address for a user
     * 
     * @param userId       The unique identifier of the user
     * @param addressIndex The index of the address to set as default
     * @param updatedBy    The identifier of the admin performing the update
     * @return The updated user object
     * @throws RuntimeException if user not found or invalid address index
     */
    public User changeDefaultAddress(String userId, int addressIndex, String updatedBy) {
        User user = getUserById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        List<Address> addresses = user.getAddresses();
        if (addresses == null || addresses.isEmpty()) {
            throw new RuntimeException("User has no addresses");
        }

        if (addressIndex < 0 || addressIndex >= addresses.size()) {
            throw new RuntimeException("Invalid address index: " + addressIndex);
        }

        // Set all addresses to non-default first
        for (Address address : addresses) {
            address.setIsDefault(false);
        }

        // Set the selected address as default
        addresses.get(addressIndex).setIsDefault(true);

        user.setAddresses(addresses);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(updatedBy);

        return userProfileRepository.updateUser(user);
    }

    /**
     * Updates user role and synchronizes with AWS Cognito groups
     * 
     * @param userId    The unique identifier of the user
     * @param newRole   The new role to assign (USER, ADMIN, SUPPORT)
     * @param updatedBy The identifier of the admin performing the update
     * @return The updated user object
     * @throws RuntimeException if user not found or Cognito operation fails
     */
    public User updateUserRole(String userId, UserRole newRole, String updatedBy) {
        User user = getUserById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        UserRole oldRole = user.getRole();
        String userEmail = user.getEmail();

        try {
            // Remove user from old Cognito group if it exists
            if (oldRole != null && !oldRole.equals(newRole)) {
                removeUserFromCognitoGroup(userEmail, oldRole.name());
            }

            // Add user to new Cognito group
            addUserToCognitoGroup(userEmail, newRole.name());

            // Update user role in DynamoDB
            user.setRole(newRole);
            user.setUpdatedAt(Instant.now());
            user.setUpdatedBy(updatedBy);

            return userProfileRepository.updateUser(user);

        } catch (Exception e) {
            throw new RuntimeException("Failed to update user role: " + e.getMessage(), e);
        }
    }

    /**
     * Marks a user as verified
     * 
     * @param userId    The unique identifier of the user
     * @param updatedBy The identifier of the admin performing the verification
     * @return The updated user object
     * @throws RuntimeException if user not found
     */
    public User verifyUser(String userId, String updatedBy) {
        User user = getUserById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        user.setVerified(true);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(updatedBy);

        // Confirm user in Cognito as well
        confirmCognitoUser(user.getEmail());

        return userProfileRepository.updateUser(user);
    }

    /**
     * Adds user to AWS Cognito group
     * 
     * @param userEmail The email of the user (Cognito username)
     * @param groupName The name of the group to add user to
     */
    private void addUserToCognitoGroup(String userEmail, String groupName) {
        try {
            AdminAddUserToGroupRequest request = AdminAddUserToGroupRequest.builder()
                    .userPoolId(userPoolId)
                    .username(userEmail)
                    .groupName(groupName)
                    .build();

            cognitoClient.adminAddUserToGroup(request);
        } catch (ResourceNotFoundException e) {
            // Group doesn't exist, create it first
            createCognitoGroup(groupName);
            // Retry adding user to group
            AdminAddUserToGroupRequest request = AdminAddUserToGroupRequest.builder()
                    .userPoolId(userPoolId)
                    .username(userEmail)
                    .groupName(groupName)
                    .build();
            cognitoClient.adminAddUserToGroup(request);
        }
    }

    /**
     * Removes user from AWS Cognito group
     * 
     * @param userEmail The email of the user (Cognito username)
     * @param groupName The name of the group to remove user from
     */
    private void removeUserFromCognitoGroup(String userEmail, String groupName) {
        try {
            AdminRemoveUserFromGroupRequest request = AdminRemoveUserFromGroupRequest.builder()
                    .userPoolId(userPoolId)
                    .username(userEmail)
                    .groupName(groupName)
                    .build();

            cognitoClient.adminRemoveUserFromGroup(request);
        } catch (Exception e) {
            // Log error but don't fail the operation
            System.err.println("Failed to remove user from group " + groupName + ": " + e.getMessage());
        }
    }

    /**
     * Creates a new Cognito group if it doesn't exist
     * 
     * @param groupName The name of the group to create
     */
    private void createCognitoGroup(String groupName) {
        try {
            CreateGroupRequest request = CreateGroupRequest.builder()
                    .userPoolId(userPoolId)
                    .groupName(groupName)
                    .description("Auto-created group for " + groupName + " role")
                    .build();

            cognitoClient.createGroup(request);
        } catch (Exception e) {
            System.err.println("Failed to create group " + groupName + ": " + e.getMessage());
        }
    }

    /**
     * Saves a new user to the database
     * 
     * @param user The user object to save
     * @return The saved user object
     * @throws RuntimeException if saving fails
     */
    public User saveUser(User user) {
        try {
            return userProfileRepository.saveUser(user);
        } catch (Exception e) {
            throw new RuntimeException("Failed to save user: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a new user in Cognito and DynamoDB
     * 
     * @param email     User's email address
     * @param role      User's role (USER, ADMIN, SUPPORT)
     * @param name      User's full name
     * @param createdBy Admin who created the user
     * @return Map containing username, password, and uuid
     * @throws RuntimeException if user creation fails
     */
    public Map<String, String> createUser(String email, UserRole role, String name, String createdBy) {
        try {
            // Generate username from email (part before @)
            String username = email.split("@")[0];

            // Generate random password
            String password = generateRandomPassword();

            // Create user in Cognito
            String cognitoUsername = createCognitoUser(email, password, name);

            // Verify user in Cognito
            verifyCognitoUser(cognitoUsername);

            // Add user to appropriate Cognito group
            addUserToCognitoGroup(cognitoUsername, role.name());

            // Create user in DynamoDB
            User user = new User();
            user.setUserId(java.util.UUID.randomUUID().toString()); // UUID for userId
            user.setUsername(username);
            user.setCustName(name);
            user.setEmail(email);
            user.setRole(role);
            user.setVerified(true);
            user.setKycVerified(false);
            user.setAccountStatus(UserStatus.ACTIVE);
            user.setFraudRisk(FraudRisk.LOW);
            user.setCreatedAt(Instant.now());
            user.setUpdatedAt(Instant.now());
            user.setCreatedBy(createdBy);
            user.setUpdatedBy(createdBy);
            user.setDeleteStatus(User.DeleteStatus.createDefault());
            user.setIsActive(true);

            User savedUser = userProfileRepository.saveUser(user);

            // Return response
            Map<String, String> result = new HashMap<>();
            result.put("username", cognitoUsername);
            result.put("password", password);
            result.put("uuid", savedUser.getUserId());

            return result;

        } catch (Exception e) {
            throw new RuntimeException("Failed to create user: " + e.getMessage(), e);
        }
    }

    /**
     * Restores a soft-deleted user
     * 
     * @param userId     The unique identifier of the user to restore
     * @param restoredBy The identifier of the admin performing the restoration
     * @return The restored user object
     * @throws RuntimeException if user not found or not deleted
     */
    public User restoreUser(String userId, String restoredBy) {
        User user = getUserById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        if (user.getDeleteStatus() == null || !user.getDeleteStatus().getIsDeleted()) {
            throw new RuntimeException("User is not deleted");
        }

        // Update delete status
        User.DeleteStatus deleteStatus = user.getDeleteStatus();
        deleteStatus.setIsDeleted(false);
        deleteStatus.setRestoreAt(Instant.now());
        deleteStatus.setRestoresCount(deleteStatus.getRestoresCount() + 1);

        user.setDeleteStatus(deleteStatus);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(restoredBy);
        user.setIsActive(true);

        // Enable user in Cognito
        enableCognitoUser(user.getEmail());

        return userProfileRepository.updateUser(user);
    }

    /**
     * Marks a user's KYC as verified
     * 
     * @param userId    The unique identifier of the user
     * @param updatedBy The identifier of the admin performing the verification
     * @return The updated user object
     * @throws RuntimeException if user not found
     */
    public User verifyUserKyc(String userId, String updatedBy) {
        User user = getUserById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        user.setKycVerified(true);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(updatedBy);

        return userProfileRepository.updateUser(user);
    }

    /**
     * Updates user status
     * 
     * @param userId    The unique identifier of the user
     * @param status    The new status to assign
     * @param updatedBy The identifier of the admin performing the update
     * @return The updated user object
     * @throws RuntimeException if user not found
     */
    public User updateUserStatus(String userId, UserStatus status, String updatedBy) {
        User user = getUserById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        user.setAccountStatus(status);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(updatedBy);

        // Update Cognito user status based on the new status
        updateCognitoUserStatus(user.getEmail(), status);

        return userProfileRepository.updateUser(user);
    }

    /**
     * Updates user fraud risk level
     * 
     * @param userId    The unique identifier of the user
     * @param fraudRisk The new fraud risk level to assign
     * @param updatedBy The identifier of the admin performing the update
     * @return The updated user object
     * @throws RuntimeException if user not found
     */
    public User updateUserFraudRisk(String userId, FraudRisk fraudRisk, String updatedBy) {
        User user = getUserById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        user.setFraudRisk(fraudRisk);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(updatedBy);

        return userProfileRepository.updateUser(user);
    }

    /**
     * Creates a user in AWS Cognito
     */
    private String createCognitoUser(String email, String password, String name) {
        try {
            AdminCreateUserRequest request = AdminCreateUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(email)
                    .temporaryPassword(password)
                    .messageAction(MessageActionType.SUPPRESS) // Don't send welcome email
                    .userAttributes(
                            AttributeType.builder()
                                    .name("email")
                                    .value(email)
                                    .build(),
                            AttributeType.builder()
                                    .name("name")
                                    .value(name)
                                    .build(),
                            AttributeType.builder()
                                    .name("email_verified")
                                    .value("true")
                                    .build())
                    .build();

            AdminCreateUserResponse response = cognitoClient.adminCreateUser(request);
            return response.user().username();

        } catch (Exception e) {
            throw new RuntimeException("Failed to create Cognito user: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies a user in Cognito by setting permanent password
     */
    private void verifyCognitoUser(String username) {
        try {
            AdminSetUserPasswordRequest request = AdminSetUserPasswordRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .password(generateRandomPassword())
                    .permanent(true)
                    .build();

            cognitoClient.adminSetUserPassword(request);
        } catch (Exception e) {
            throw new RuntimeException("Failed to verify Cognito user: " + e.getMessage(), e);
        }
    }

    /**
     * Confirms a user in Cognito (marks them as verified)
     */
    private void confirmCognitoUser(String email) {
        try {
            AdminConfirmSignUpRequest request = AdminConfirmSignUpRequest.builder()
                    .userPoolId(userPoolId)
                    .username(email)
                    .build();

            cognitoClient.adminConfirmSignUp(request);
        } catch (Exception e) {
            System.err.println("Failed to confirm Cognito user (may already be confirmed): " + e.getMessage());
        }
    }

    /**
     * Enables a user in Cognito
     */
    private void enableCognitoUser(String email) {
        try {
            AdminEnableUserRequest request = AdminEnableUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(email)
                    .build();

            cognitoClient.adminEnableUser(request);
        } catch (Exception e) {
            System.err.println("Failed to enable Cognito user: " + e.getMessage());
        }
    }

    /**
     * Disables a user in Cognito
     */
    private void disableCognitoUser(String email) {
        try {
            AdminDisableUserRequest request = AdminDisableUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(email)
                    .build();

            cognitoClient.adminDisableUser(request);
        } catch (Exception e) {
            System.err.println("Failed to disable Cognito user: " + e.getMessage());
        }
    }

    /**
     * Updates Cognito user status based on application status
     */
    private void updateCognitoUserStatus(String email, UserStatus status) {
        try {
            if (status == UserStatus.BANNED || status == UserStatus.SUSPENDED) {
                disableCognitoUser(email);
            } else if (status == UserStatus.ACTIVE) {
                enableCognitoUser(email);
            }
            // INACTIVE status doesn't change Cognito status
        } catch (Exception e) {
            System.err.println("Failed to update Cognito user status: " + e.getMessage());
        }
    }

    /**
     * Generates a random password
     */
    private String generateRandomPassword() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        StringBuilder password = new StringBuilder();
        java.util.Random random = new java.util.Random();

        for (int i = 0; i < 12; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }

        return password.toString();
    }
}