package com.shop.user.service;

import com.shop.user.dto.CognitoUserCreationResponse;
import com.shop.user.dto.UserCreationResponse;
import com.shop.user.model.User;
import com.shop.user.enums.UserRole;
import com.shop.user.enums.CognitoUserStatus;
import com.shop.user.enums.FraudRisk;
import com.shop.user.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * User Service for business logic operations
 * 
 * This service contains all the business logic for user management operations,
 * keeping the controller thin and focused on HTTP concerns.
 * 
 * Features:
 * ✅ User CRUD operations with DynamoDB
 * ✅ AWS Cognito integration for authentication
 * ✅ User verification and status management
 * ✅ Role and permission management with Cognito groups
 * ✅ Soft delete functionality (DynamoDB + Cognito disable)
 * ✅ Address management
 * ✅ Audit trail with admin tracking
 * 
 * @author Vikas Singh
 * @version 2.0
 * @since 2025-09-21
 */
@Service
public class UserService {

    private final UserRepository userRepository;
    private final CognitoService cognitoService;

    public UserService(UserRepository userRepository, CognitoService cognitoService) {
        this.userRepository = userRepository;
        this.cognitoService = cognitoService;
    }

    /**
     * Get all users from the repository
     * 
     * @return List of all users
     */
    public List<User> getAllUsers() {
        return userRepository.getAllUsers();
    }

    /**
     * Get a user by ID
     * 
     * @param userId User ID to retrieve
     * @return Optional containing the user if found
     * @throws RuntimeException if user not found
     */
    public User getUserById(String userId) {
        return userRepository.getUserById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));
    }

    /**
     * Get a user by ID (returns Optional)
     * 
     * @param userId User ID to retrieve
     * @return Optional containing the user if found
     */
    public Optional<User> findUserById(String userId) {
        return userRepository.getUserById(userId);
    }

    /**
     * Get a user by email
     * 
     * @param email User email to search for
     * @return User if found, null otherwise
     */
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }

    /**
     * Create a new user in both DynamoDB and Cognito
     * 
     * @param email   User email
     * @param role    User role (determines Cognito group)
     * @param name    User name
     * @param adminId Admin ID performing the action
     * @return UserCreationResponse containing creation result with Cognito
     *         credentials
     */
    public UserCreationResponse createUser(String email, UserRole role, String name, String adminId) {
        // Validate input
        if (email == null || email.trim().isEmpty()) {
            throw new RuntimeException("Email is required");
        }
        if (name == null || name.trim().isEmpty()) {
            throw new RuntimeException("Name is required");
        }

        try {
            // Step 1: Create user in Cognito first
            CognitoUserCreationResponse cognitoResult = cognitoService.createCognitoUser(email, name, role);
            String cognitoUsername = cognitoResult.getUsername();
            String temporaryPassword = cognitoResult.getTemporaryPassword();

            // Step 2: Create user in DynamoDB
            User newUser = User.builder()
                    .userId(java.util.UUID.randomUUID().toString())
                    .username(cognitoUsername) // Use Cognito username
                    .custName(name)
                    .email(email)
                    .roles(List.of(role)) // Convert single role to list
                    .userStatus(CognitoUserStatus.CONFIRMED) // Default for admin-created users
                    .enabled(true) // Admin-created users are enabled by default
                    .kycVerified(false)
                    .fraudRisk(FraudRisk.LOW)
                    .isActive(true)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .createdBy(adminId)
                    .updatedBy(adminId)
                    .deleteStatus(User.DeleteStatus.createDefault())
                    .build();

            userRepository.saveUser(newUser);

            System.out.println("USER_SERVICE: User created successfully in both Cognito and DynamoDB - " + email);

            // Return comprehensive result
            return new UserCreationResponse(
                    newUser.getUserId(),
                    cognitoUsername,
                    newUser.getEmail(),
                    temporaryPassword,
                    role,
                    "created");

        } catch (Exception e) {
            System.err.println("USER_SERVICE: Failed to create user - " + e.getMessage());
            // If DynamoDB fails after Cognito success, we should clean up Cognito
            // For now, we'll let the error propagate
            throw new RuntimeException("Failed to create user: " + e.getMessage());
        }
    }

    /**
     * Verify a user account
     * 
     * @param userId  User ID to verify
     * @param adminId Admin ID performing the action
     * @return Updated user
     */
    public User verifyUser(String userId, String adminId) {
        User user = getUserById(userId);

        // Check if user is already verified/enabled
        if (Boolean.TRUE.equals(user.getEnabled())) {
            System.out.println("USER_SERVICE: User is already enabled - " + user.getEmail());
            // Return the user instead of throwing exception - this is a successful
            // operation
            return user;
        }

        // Confirm user in Cognito User Pool
        try {
            cognitoService.confirmUser(user.getEmail());
            System.out.println("USER_SERVICE: User confirmed in Cognito - " + user.getEmail());
        } catch (Exception e) {
            System.err.println(
                    "USER_SERVICE: Failed to confirm user in Cognito - " + user.getEmail() + ": " + e.getMessage());
            throw new RuntimeException("Failed to confirm user in Cognito: " + e.getMessage());
        }

        user.setEnabled(true);
        user.setUserStatus(CognitoUserStatus.CONFIRMED);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(adminId);

        System.out.println("USER_SERVICE: User verified successfully - " + user.getEmail());

        return userRepository.saveUser(user);
    }

    /**
     * Update user role in both DynamoDB and Cognito groups (legacy method)
     * 
     * @param userId  User ID to update
     * @param role    New role (will move user to corresponding Cognito group)
     * @param adminId Admin ID performing the action
     * @return Updated user
     */
    public User updateUserRole(String userId, UserRole role, String adminId) {
        return updateUserRoles(userId, List.of(role), adminId);
    }

    /**
     * Update user roles in both DynamoDB and Cognito groups (supports multiple
     * roles)
     * 
     * @param userId   User ID to update
     * @param newRoles List of new roles (will update Cognito groups accordingly)
     * @param adminId  Admin ID performing the action
     * @return Updated user
     */
    public User updateUserRoles(String userId, List<UserRole> newRoles, String adminId) {
        if (newRoles == null || newRoles.isEmpty()) {
            throw new IllegalArgumentException("At least one role must be specified");
        }

        User user = getUserById(userId);
        List<UserRole> oldRoles = user.getRoles();

        // Step 1: Update roles in Cognito groups
        try {
            cognitoService.updateUserRoles(user.getEmail(), oldRoles, newRoles);
        } catch (Exception e) {
            System.err.println("USER_SERVICE: Failed to update Cognito roles for user " + user.getEmail() + ": "
                    + e.getMessage());
            throw new RuntimeException("Failed to update user roles in Cognito: " + e.getMessage());
        }

        // Step 2: Update roles in DynamoDB
        user.setRoles(newRoles);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(adminId);

        System.out.println("USER_SERVICE: User roles updated successfully - " + user.getUsername() + " from " + oldRoles
                + " to " + newRoles);

        return userRepository.saveUser(user);
    }

    /**
     * Update user cognito status
     * 
     * Maps CognitoUserStatus to Cognito operations:
     * - CONFIRMED: Enable user in Cognito
     * - UNCONFIRMED, ARCHIVED, COMPROMISED, RESET_REQUIRED, FORCE_CHANGE_PASSWORD:
     * Disable user in Cognito
     * 
     * @param userId  User ID to update
     * @param status  New cognito status
     * @param adminId Admin ID performing the action
     * @return Updated user
     * @throws RuntimeException if status is invalid or Cognito sync fails
     */
    public User updateUserStatus(String userId, CognitoUserStatus status, String adminId) {
        // Validate status enum
        if (status == null) {
            throw new IllegalArgumentException(
                    "Status cannot be null. Valid statuses are: UNCONFIRMED, CONFIRMED, ARCHIVED, COMPROMISED, UNKNOWN, RESET_REQUIRED, FORCE_CHANGE_PASSWORD");
        }

        User user = getUserById(userId);
        CognitoUserStatus oldStatus = user.getUserStatus();

        // Update user status in DynamoDB
        user.setUserStatus(status);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(adminId);

        // Sync with Cognito if status changed
        if (oldStatus != status) {
            try {
                switch (status) {
                    case CONFIRMED:
                        cognitoService.enableUser(user.getEmail());
                        cognitoService.setEmailVerified(user.getEmail());
                        cognitoService.confirmUserSignup(user.getEmail());
                        user.setEnabled(true);
                        System.out.println(
                                "USER_SERVICE: User enabled, email verified and signup confirmed in Cognito - "
                                        + user.getEmail());
                        break;
                    case UNCONFIRMED:
                    case ARCHIVED:
                    case COMPROMISED:
                    case RESET_REQUIRED:
                    case FORCE_CHANGE_PASSWORD:
                        cognitoService.disableUser(user.getEmail());
                        user.setEnabled(false);
                        System.out.println("USER_SERVICE: User disabled in Cognito - " + user.getEmail());
                        break;
                    default:
                        throw new IllegalArgumentException(
                                "Invalid status. Valid statuses are: UNCONFIRMED, CONFIRMED, ARCHIVED, COMPROMISED, UNKNOWN, RESET_REQUIRED, FORCE_CHANGE_PASSWORD");
                }
            } catch (IllegalArgumentException e) {
                throw e; // Re-throw validation errors
            } catch (Exception e) {
                System.err.println("USER_SERVICE: Failed to sync user status with Cognito - " + user.getEmail() + ": "
                        + e.getMessage());
                throw new RuntimeException("Failed to sync user status with Cognito: " + e.getMessage());
            }
        }

        System.out.println("USER_SERVICE: User status updated successfully - " + user.getEmail() + " from " + oldStatus
                + " to " + status);

        return userRepository.saveUser(user);
    }

    /**
     * Verify user KYC
     * 
     * @param userId  User ID to verify KYC
     * @param adminId Admin ID performing the action
     * @return Updated user
     */
    public User verifyUserKyc(String userId, String adminId) {
        User user = getUserById(userId);

        user.setKycVerified(true);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(adminId);

        return userRepository.saveUser(user);
    }

    /**
     * Update user fraud risk level
     * 
     * @param userId  User ID to update
     * @param risk    New fraud risk level
     * @param adminId Admin ID performing the action
     * @return Updated user
     */
    public User updateUserFraudRisk(String userId, FraudRisk risk, String adminId) {
        User user = getUserById(userId);

        user.setFraudRisk(risk);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(adminId);

        return userRepository.saveUser(user);
    }

    /**
     * Soft delete a user (DynamoDB + disable in Cognito)
     * 
     * @param userId  User ID to delete
     * @param adminId Admin ID performing the action
     * @return Updated user
     */
    public User softDeleteUser(String userId, String adminId) {
        User user = getUserById(userId);

        if (user.getDeleteStatus() != null && user.getDeleteStatus().getIsDeleted()) {
            throw new RuntimeException("User is already deleted");
        }

        try {
            // Step 1: Disable user in Cognito
            cognitoService.disableUser(user.getEmail());

            // Step 2: Update delete status in DynamoDB
            User.DeleteStatus deleteStatus = new User.DeleteStatus();
            deleteStatus.setIsDeleted(true);
            deleteStatus.setDeletedAt(Instant.now());
            deleteStatus
                    .setRestoresCount(user.getDeleteStatus() != null ? user.getDeleteStatus().getRestoresCount() : 0);

            user.setDeleteStatus(deleteStatus);
            user.setUpdatedAt(Instant.now());
            user.setUpdatedBy(adminId);

            System.out.println(
                    "USER_SERVICE: User soft deleted successfully - " + user.getUsername() + " (disabled in Cognito)");

            return userRepository.saveUser(user);

        } catch (Exception e) {
            System.err
                    .println("USER_SERVICE: Failed to soft delete user " + user.getUsername() + ": " + e.getMessage());
            throw new RuntimeException("Failed to soft delete user: " + e.getMessage());
        }
    }

    /**
     * Restore a soft-deleted user (DynamoDB + enable in Cognito)
     * 
     * @param userId  User ID to restore
     * @param adminId Admin ID performing the action
     * @return Updated user
     */
    public User restoreUser(String userId, String adminId) {
        User user = getUserById(userId);

        if (user.getDeleteStatus() == null || !user.getDeleteStatus().getIsDeleted()) {
            throw new RuntimeException("User is not deleted");
        }

        try {
            // Step 1: Enable user in Cognito
            cognitoService.enableUser(user.getEmail());

            // Step 2: Update delete status in DynamoDB
            User.DeleteStatus deleteStatus = user.getDeleteStatus();
            deleteStatus.setIsDeleted(false);
            deleteStatus.setRestoreAt(Instant.now());
            deleteStatus.setRestoresCount(deleteStatus.getRestoresCount() + 1);

            user.setDeleteStatus(deleteStatus);
            user.setUpdatedAt(Instant.now());
            user.setUpdatedBy(adminId);

            System.out.println(
                    "USER_SERVICE: User restored successfully - " + user.getUsername() + " (enabled in Cognito)");

            return userRepository.saveUser(user);

        } catch (Exception e) {
            System.err.println("USER_SERVICE: Failed to restore user " + user.getUsername() + ": " + e.getMessage());
            throw new RuntimeException("Failed to restore user: " + e.getMessage());
        }
    }

    /**
     * Change user's default address
     * 
     * @param userId       User ID to update
     * @param addressIndex Index of address to make default
     * @param adminId      Admin ID performing the action
     * @return Updated user
     */
    public User changeDefaultAddress(String userId, int addressIndex, String adminId) {
        User user = getUserById(userId);

        if (user.getAddresses() == null || user.getAddresses().isEmpty()) {
            throw new RuntimeException("User has no addresses to set as default");
        }

        if (addressIndex < 0 || addressIndex >= user.getAddresses().size()) {
            throw new RuntimeException("Invalid address index: " + addressIndex);
        }

        // Reset all addresses to non-default
        for (User.Address address : user.getAddresses()) {
            address.setIsDefault(false);
        }

        // Set the specified address as default
        user.getAddresses().get(addressIndex).setIsDefault(true);
        user.setUpdatedAt(Instant.now());
        user.setUpdatedBy(adminId);

        return userRepository.saveUser(user);
    }
}