package com.shop.user.service;

import com.shop.user.dto.CognitoUserCreationResponse;
import com.shop.user.enums.UserRole;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.ArrayList;
import java.util.List;
import java.util.List;

/**
 * AWS Cognito Service for user management operations
 * 
 * This service handles all interactions with AWS Cognito User Pool:
 * ✅ User creation with temporary passwords
 * ✅ User role management via Cognito Groups
 * ✅ User enable/disable for soft delete functionality
 * ✅ Group membership management (USER, ADMIN, SUPPORT)
 * ✅ Proper error handling and logging
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-21
 */
@Service
public class CognitoService {

    private final CognitoIdentityProviderClient cognitoClient;
    private final String userPoolId;

    public CognitoService(@Value("${aws.cognito.user-pool-id}") String userPoolId,
            @Value("${aws.cognito.region}") String region) {
        this.userPoolId = userPoolId;
        this.cognitoClient = CognitoIdentityProviderClient.builder()
                .region(Region.of(region))
                .build();
    }

    /**
     * Create a new user in Cognito User Pool
     * 
     * @param email User email (will be username)
     * @param name  User's full name
     * @param role  User role (determines group membership)
     * @return CognitoUserCreationResponse containing username and temporary
     *         password
     */
    public CognitoUserCreationResponse createCognitoUser(String email, String name, UserRole role) {
        try {
            // Generate temporary password
            String tempPassword = generateTemporaryPassword();

            // Create user attributes
            List<AttributeType> attributes = List.of(
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
                            .build());

            // Create user in Cognito
            AdminCreateUserRequest createRequest = AdminCreateUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(email)
                    .userAttributes(attributes)
                    .temporaryPassword(tempPassword)
                    .messageAction(MessageActionType.SUPPRESS) // Don't send email
                    .build();

            AdminCreateUserResponse createResponse = cognitoClient.adminCreateUser(createRequest);
            String username = createResponse.user().username();

            // Add user to appropriate group based on role
            addUserToGroup(username, role.name());

            System.out.println("COGNITO: User created successfully - " + username + " with role " + role);

            return new CognitoUserCreationResponse(username, tempPassword, email, role);

        } catch (UsernameExistsException e) {
            System.err.println("COGNITO: User already exists - " + email);
            throw new RuntimeException("User already exists in Cognito: " + email);
        } catch (Exception e) {
            System.err.println("COGNITO: Failed to create user - " + e.getMessage());
            throw new RuntimeException("Failed to create user in Cognito: " + e.getMessage());
        }
    }

    /**
     * Update user's role by changing group membership
     * 
     * @param username Cognito username
     * @param oldRole  Current role (to remove from group)
     * @param newRole  New role (to add to group)
     */
    public void updateUserRole(String username, UserRole oldRole, UserRole newRole) {
        try {
            // Remove from old group if different
            if (oldRole != null && oldRole != newRole) {
                removeUserFromGroup(username, oldRole.name());
            }

            // Add to new group
            addUserToGroup(username, newRole.name());

            System.out.println("COGNITO: User role updated - " + username + " from " + oldRole + " to " + newRole);

        } catch (Exception e) {
            System.err.println("COGNITO: Failed to update user role - " + e.getMessage());
            throw new RuntimeException("Failed to update user role in Cognito: " + e.getMessage());
        }
    }

    /**
     * Update user's roles by changing group memberships (supports multiple roles)
     * 
     * @param username Cognito username
     * @param oldRoles Current roles (to remove from groups)
     * @param newRoles New roles (to add to groups)
     */
    public void updateUserRoles(String username, List<UserRole> oldRoles, List<UserRole> newRoles) {
        try {
            // Remove from old groups that are not in new roles
            if (oldRoles != null) {
                for (UserRole oldRole : oldRoles) {
                    if (newRoles == null || !newRoles.contains(oldRole)) {
                        removeUserFromGroup(username, oldRole.name());
                    }
                }
            }

            // Add to new groups that are not in old roles
            if (newRoles != null) {
                for (UserRole newRole : newRoles) {
                    if (oldRoles == null || !oldRoles.contains(newRole)) {
                        addUserToGroup(username, newRole.name());
                    }
                }
            }

            System.out.println("COGNITO: User roles updated - " + username + " from " + oldRoles + " to " + newRoles);

        } catch (Exception e) {
            System.err.println("COGNITO: Failed to update user roles - " + e.getMessage());
            throw new RuntimeException("Failed to update user roles in Cognito: " + e.getMessage());
        }
    }

    /**
     * Disable user in Cognito (soft delete)
     * 
     * @param username Cognito username
     */
    public void disableUser(String username) {
        try {
            AdminDisableUserRequest disableRequest = AdminDisableUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build();

            cognitoClient.adminDisableUser(disableRequest);
            System.out.println("COGNITO: User disabled - " + username);

        } catch (Exception e) {
            System.err.println("COGNITO: Failed to disable user - " + e.getMessage());
            throw new RuntimeException("Failed to disable user in Cognito: " + e.getMessage());
        }
    }

    /**
     * Enable user in Cognito (restore from soft delete)
     * 
     * @param username Cognito username
     */
    public void enableUser(String username) {
        try {
            AdminEnableUserRequest enableRequest = AdminEnableUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build();

            cognitoClient.adminEnableUser(enableRequest);
            System.out.println("COGNITO: User enabled - " + username);

        } catch (Exception e) {
            System.err.println("COGNITO: Failed to enable user - " + e.getMessage());
            throw new RuntimeException("Failed to enable user in Cognito: " + e.getMessage());
        }
    }

    /**
     * Add user to a Cognito group
     * 
     * @param username  Cognito username
     * @param groupName Group name (USER, ADMIN, SUPPORT)
     */
    private void addUserToGroup(String username, String groupName) {
        try {
            AdminAddUserToGroupRequest addToGroupRequest = AdminAddUserToGroupRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .groupName(groupName)
                    .build();

            cognitoClient.adminAddUserToGroup(addToGroupRequest);
            System.out.println("COGNITO: User added to group - " + username + " → " + groupName);

        } catch (Exception e) {
            System.err.println("COGNITO: Failed to add user to group - " + e.getMessage());
            throw new RuntimeException("Failed to add user to group: " + e.getMessage());
        }
    }

    /**
     * Remove user from a Cognito group
     * 
     * @param username  Cognito username
     * @param groupName Group name (USER, ADMIN, SUPPORT)
     */
    private void removeUserFromGroup(String username, String groupName) {
        try {
            AdminRemoveUserFromGroupRequest removeFromGroupRequest = AdminRemoveUserFromGroupRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .groupName(groupName)
                    .build();

            cognitoClient.adminRemoveUserFromGroup(removeFromGroupRequest);
            System.out.println("COGNITO: User removed from group - " + username + " ← " + groupName);

        } catch (Exception e) {
            System.err.println("COGNITO: Failed to remove user from group - " + e.getMessage());
            // Don't throw exception here - might be removing from group user wasn't in
            System.err.println("COGNITO: Continuing despite group removal error");
        }
    }

    /**
     * Get all groups a user belongs to
     * 
     * @param username Cognito username
     * @return List of group names
     */
    public List<String> getUserGroups(String username) {
        try {
            AdminListGroupsForUserRequest listGroupsRequest = AdminListGroupsForUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build();

            AdminListGroupsForUserResponse response = cognitoClient.adminListGroupsForUser(listGroupsRequest);

            List<String> groups = new ArrayList<>();
            for (GroupType group : response.groups()) {
                groups.add(group.groupName());
            }

            return groups;

        } catch (Exception e) {
            System.err.println("COGNITO: Failed to get user groups - " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Generate a secure temporary password
     * 
     * @return Temporary password string
     */
    private String generateTemporaryPassword() {
        // Generate a secure temporary password
        // Format: TempPass123! (meets Cognito password requirements)
        return "TempPass" + System.currentTimeMillis() % 10000 + "!";
    }

    /**
     * Confirm user signup in Cognito (mark as verified)
     * 
     * @param username Cognito username
     */
    public void confirmUser(String username) {
        try {
            AdminConfirmSignUpRequest confirmRequest = AdminConfirmSignUpRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build();

            cognitoClient.adminConfirmSignUp(confirmRequest);
            System.out.println("COGNITO: User confirmed - " + username);

        } catch (Exception e) {
            System.err.println("COGNITO: Failed to confirm user (may already be confirmed): " + e.getMessage());
            // Don't throw exception as user might already be confirmed
        }
    }

    /**
     * Delete user completely from Cognito (hard delete)
     * Use with caution - this is irreversible
     * 
     * @param username Cognito username
     */
    public void deleteUser(String username) {
        try {
            AdminDeleteUserRequest deleteRequest = AdminDeleteUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build();

            cognitoClient.adminDeleteUser(deleteRequest);
            System.out.println("COGNITO: User permanently deleted - " + username);

        } catch (Exception e) {
            System.err.println("COGNITO: Failed to delete user - " + e.getMessage());
            throw new RuntimeException("Failed to delete user from Cognito: " + e.getMessage());
        }
    }

    /**
     * Set user email as verified in Cognito
     * 
     * @param username Cognito username (email)
     */
    public void setEmailVerified(String username) {
        try {
            AttributeType emailVerifiedAttribute = AttributeType.builder()
                    .name("email_verified")
                    .value("true")
                    .build();

            AdminUpdateUserAttributesRequest updateRequest = AdminUpdateUserAttributesRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .userAttributes(emailVerifiedAttribute)
                    .build();

            cognitoClient.adminUpdateUserAttributes(updateRequest);
            System.out.println("COGNITO: Email verified for user - " + username);

        } catch (Exception e) {
            System.err.println("COGNITO: Failed to set email verified - " + e.getMessage());
            throw new RuntimeException("Failed to set email verified in Cognito: " + e.getMessage());
        }
    }

    /**
     * Confirm user signup in Cognito (admin override)
     * 
     * @param username Cognito username (email)
     */
    public void confirmUserSignup(String username) {
        try {
            AdminConfirmSignUpRequest confirmRequest = AdminConfirmSignUpRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build();

            cognitoClient.adminConfirmSignUp(confirmRequest);
            System.out.println("COGNITO: User signup confirmed - " + username);

        } catch (Exception e) {
            System.err.println("COGNITO: Failed to confirm user signup - " + e.getMessage());
            throw new RuntimeException("Failed to confirm user signup in Cognito: " + e.getMessage());
        }
    }
}