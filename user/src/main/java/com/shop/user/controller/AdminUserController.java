package com.shop.user.controller;

import com.shop.user.dto.ApiResponse;
import com.shop.user.dto.UserCreationRequest;
import com.shop.user.dto.UserCreationResponse;
import com.shop.user.model.User;
import com.shop.user.enums.UserRole;
import com.shop.user.enums.CognitoUserStatus;
import com.shop.user.enums.FraudRisk;
import com.shop.user.service.UserService;
import com.shop.user.service.AdminSecurityService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

/**
 * Admin User Controller for User Service
 * 
 * 🔒 SECURITY: ALL ENDPOINTS REQUIRE ADMIN AUTHENTICATION via @PreAuthorize
 * 
 * Features:
 * ✅ JWT-based authentication with Cognito
 * ✅ ADMIN group verification for access control
 * ✅ Method-level security with @PreAuthorize annotations
 * ✅ Secure user data access from DynamoDB
 * ✅ Complete CRUD operations for user management
 * ✅ Centralized business logic in UserService
 * 
 * Security Flow:
 * 1. @PreAuthorize("@adminSecurityService.isAdmin()") - Declarative security
 * 2. JWT token extraction from access_token cookie
 * 3. Token signature verification using Cognito JWKS
 * 4. Token expiry and issuer validation
 * 5. ADMIN group membership verification
 * 
 * @author Vikas Singh
 * @version 3.0
 * @since 2025-09-21
 * @reference Spring Security @PreAuthorize
 */
@RestController
@RequestMapping("/admin")
public class AdminUserController {

    private final UserService userService;
    private final AdminSecurityService adminSecurityService;

    public AdminUserController(UserService userService, AdminSecurityService adminSecurityService) {
        this.userService = userService;
        this.adminSecurityService = adminSecurityService;
    }

    /**
     * Get all users from DynamoDB
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * @param limit Optional limit for number of users to retrieve
     * @return ResponseEntity with ApiResponse containing list of users
     */
    @GetMapping("/users")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<List<User>>> getAllUsers(
            @RequestParam(required = false) Integer limit) {
        try {
            List<User> users = userService.getAllUsers();
            return ResponseEntity.ok(
                    ApiResponse.success("Users retrieved successfully", users));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to retrieve users: " + e.getMessage(), 500));
        }
    }

    /**
     * Get a specific user by ID
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * @param uuid User ID to retrieve
     * @return ResponseEntity with ApiResponse containing user data
     */
    @GetMapping("/users/{uuid}")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> getUserById(@PathVariable String uuid) {
        try {
            Optional<User> userOpt = userService.findUserById(uuid);
            if (userOpt.isPresent()) {
                return ResponseEntity.ok(
                        ApiResponse.success("User retrieved successfully", userOpt.get()));
            } else {
                return ResponseEntity.status(404).body(
                        ApiResponse.error("User not found with ID: " + uuid, 404));
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to retrieve user: " + e.getMessage(), 500));
        }
    }

    /**
     * Create a new user
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * @param userCreationRequest UserCreationRequest containing user creation data
     * @return ResponseEntity with ApiResponse containing creation result
     */
    @PostMapping("/users")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<UserCreationResponse>> createUser(
            @RequestBody UserCreationRequest userCreationRequest) {
        try {
            String email = userCreationRequest.getEmail();
            UserRole role = userCreationRequest.getRole();
            String name = userCreationRequest.getName();

            if (email == null || role == null || name == null) {
                return ResponseEntity.status(400).body(
                        ApiResponse.error("Missing required fields: email, role, name", 400));
            }

            String adminId = adminSecurityService.getCurrentAdminId();

            UserCreationResponse result = userService.createUser(email, role, name, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User created successfully", result));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error("Invalid role. Must be USER, ADMIN, or SUPPORT", 400));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to create user: " + e.getMessage(), 500));
        }
    }

    /**
     * Soft delete a user
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * @param uuid User ID to delete
     * @return ResponseEntity with ApiResponse containing updated user
     */
    @DeleteMapping("/users/{uuid}")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> softDeleteUser(@PathVariable String uuid) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User user = userService.softDeleteUser(uuid, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User deleted successfully", user));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to delete user: " + e.getMessage(), 500));
        }
    }

    /**
     * Restore a soft-deleted user
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * @param uuid User ID to restore
     * @return ResponseEntity with ApiResponse containing updated user
     */
    @PostMapping("/users/{uuid}/restore")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> restoreUser(@PathVariable String uuid) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User user = userService.restoreUser(uuid, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User restored successfully", user));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to restore user: " + e.getMessage(), 500));
        }
    }

    /**
     * Update user default address
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * @param uuid         User ID to update
     * @param addressIndex Index of address to make default
     * @return ResponseEntity with ApiResponse containing updated user
     */
    @PutMapping("/users/{uuid}/address")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> changeDefaultAddress(
            @PathVariable String uuid,
            @RequestParam int addressIndex) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User updatedUser = userService.changeDefaultAddress(uuid, addressIndex, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("Default address updated successfully", updatedUser));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to update default address: " + e.getMessage(), 500));
        }
    }

    /**
     * Update user verification status
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * @param uuid User ID to verify
     * @return ResponseEntity with ApiResponse containing updated user
     */
    @PutMapping("/users/{uuid}/verify")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> verifyUser(@PathVariable String uuid) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User user = userService.verifyUser(uuid, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User verified successfully", user));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to verify user: " + e.getMessage(), 500));
        }
    }

    /**
     * Update user role
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * @param uuid    User ID to update
     * @param roleStr New role for the user as string
     * @return ResponseEntity with ApiResponse containing updated user
     */
    @PutMapping("/users/{uuid}/role")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> updateUserRole(
            @PathVariable String uuid,
            @RequestParam String role) {
        try {
            // Validate role enum
            UserRole userRole;
            try {
                userRole = UserRole.valueOf(role.toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.status(400).body(
                        ApiResponse.error("No such role found. Valid roles are: USER, ADMIN, SUPPORT", 400));
            }

            String adminId = adminSecurityService.getCurrentAdminId();
            User user = userService.updateUserRole(uuid, userRole, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User role updated successfully", user));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to update user role: " + e.getMessage(), 500));
        }
    }

    /**
     * Update user KYC verification status
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * @param uuid User ID to update
     * @return ResponseEntity with ApiResponse containing updated user
     */
    @PutMapping("/users/{uuid}/verify-kyc")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> verifyUserKyc(@PathVariable String uuid) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User user = userService.verifyUserKyc(uuid, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User KYC verified successfully", user));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to verify user KYC: " + e.getMessage(), 500));
        }
    }

    /**
     * Update user account status
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * Supported statuses: ACTIVE, INACTIVE, SUSPENDED, BANNED
     * - ACTIVE: Enables user in Cognito
     * - INACTIVE, SUSPENDED, BANNED: Disables user in Cognito
     * 
     * @param uuid   User ID to update
     * @param status New account status
     * @return ResponseEntity with ApiResponse containing updated user
     */
    @PutMapping("/users/{uuid}/status")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> updateUserStatus(
            @PathVariable String uuid,
            @RequestParam CognitoUserStatus status) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User user = userService.updateUserStatus(uuid, status, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User status updated successfully", user));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error("Invalid status. Valid statuses are: ACTIVE, INACTIVE, SUSPENDED, BANNED", 400));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to update user status: " + e.getMessage(), 500));
        }
    }

    /**
     * Update user fraud risk level
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * @param uuid User ID to update
     * @param risk New fraud risk level
     * @return ResponseEntity with ApiResponse containing updated user
     */
    @PutMapping("/users/{uuid}/risk")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> updateUserFraudRisk(
            @PathVariable String uuid,
            @RequestParam FraudRisk risk) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User user = userService.updateUserFraudRisk(uuid, risk, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User fraud risk updated successfully", user));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to update user fraud risk: " + e.getMessage(), 500));
        }
    }
}