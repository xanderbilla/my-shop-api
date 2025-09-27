package com.shop.user.controller;

import com.shop.user.dto.ApiResponse;
import com.shop.user.dto.UserCreationRequest;
import com.shop.user.dto.UserCreationResponse;
import com.shop.user.dto.UpdateRoleRequest;
import com.shop.user.dto.UpdateStatusRequest;
import com.shop.user.dto.UpdateRiskRequest;
import com.shop.user.dto.UserFilterRequest;
import com.shop.user.dto.PaginatedResponse;
import com.shop.user.model.User;
import com.shop.user.enums.UserRole;
import com.shop.user.service.UserService;
import java.util.List;
import com.shop.user.service.AdminSecurityService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;

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
     * Get all users with filtering, sorting, and pagination support
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * Query parameters:
     * - query: Filter users by full/partial username, custName, email, phone match
     * (default: null)
     * - userStatus: User status filter - CONFIRMED (default), UNCONFIRMED,
     * ARCHIVED, COMPROMISED, UNKNOWN, RESET_REQUIRED, FORCE_CHANGE_PASSWORD
     * - role: Filter by assigned role - USER (default), ADMIN, SUPPORT
     * - page: Page number (default: 1)
     * - limit: Records per page (default: 10)
     * - sortBy: Field to sort by - createdAt (default), updatedAt, lastLogin
     * - sortOrder: Sort order - asc (default) or desc
     * 
     * @param query      Search query for username, custName, email, phone
     * @param userStatus User status filter
     * @param role       Role filter
     * @param page       Page number (default: 1)
     * @param limit      Records per page (default: 10)
     * @param sortBy     Field to sort by (default: createdAt)
     * @param sortOrder  Sort order - 'asc' or 'desc' (default: asc)
     * @return Paginated response with users and pagination metadata
     */
    @GetMapping("/users")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<PaginatedResponse<User>>> getAllUsers(
            @RequestParam(required = false) String query,
            @RequestParam(required = false, defaultValue = "CONFIRMED") com.shop.user.enums.CognitoUserStatus userStatus,
            @RequestParam(required = false, defaultValue = "USER") UserRole role,
            @RequestParam(required = false, defaultValue = "1") Integer page,
            @RequestParam(required = false, defaultValue = "10") Integer limit,
            @RequestParam(required = false, defaultValue = "createdAt") String sortBy,
            @RequestParam(required = false, defaultValue = "asc") String sortOrder) {
        try {
            // Create filter request
            UserFilterRequest filterRequest = new UserFilterRequest(query, userStatus, role, page, limit, sortBy,
                    sortOrder);

            PaginatedResponse<User> paginatedUsers = userService.getFilteredUsers(filterRequest);
            return ResponseEntity.ok(
                    ApiResponse.success("Users retrieved successfully", paginatedUsers));
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
            List<UserRole> roles = userCreationRequest.getRoles();
            String name = userCreationRequest.getName();

            if (email == null || roles == null || roles.isEmpty() || name == null) {
                return ResponseEntity.status(400).body(
                        ApiResponse.error("Missing required fields: email, roles, name", 400));
            }

            String adminId = adminSecurityService.getCurrentAdminId();

            UserCreationResponse result = userService.createUser(email, roles, name, adminId);
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
            userService.softDeleteUser(uuid, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User deleted successfully"));
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
            userService.restoreUser(uuid, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User restored successfully"));
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
            userService.verifyUser(uuid, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User verified successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to verify user: " + e.getMessage(), 500));
        }
    }

    /**
     * Update user roles
     * 
     * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
     * 
     * @param uuid    User ID to update
     * @param request Request body containing list of roles
     * @return ResponseEntity with ApiResponse containing updated user
     */
    @PutMapping("/users/{uuid}/roles")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> updateUserRoles(
            @PathVariable String uuid,
            @RequestBody @Valid UpdateRoleRequest request) {
        String adminId = adminSecurityService.getCurrentAdminId();
        userService.updateUserRoles(uuid, request.getRoles(), adminId);
        return ResponseEntity.ok(
                ApiResponse.success("User roles updated successfully"));
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
            userService.verifyUserKyc(uuid, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User KYC verified successfully"));
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
     * Supported statuses: UNCONFIRMED, CONFIRMED, ARCHIVED, COMPROMISED, UNKNOWN,
     * RESET_REQUIRED, FORCE_CHANGE_PASSWORD
     * - CONFIRMED: Enables user in Cognito
     * - Other statuses: Disables user in Cognito
     * 
     * @param uuid    User ID to update
     * @param request Request body containing new status
     * @return ResponseEntity with ApiResponse containing updated user
     */
    @PutMapping("/users/{uuid}/status")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> updateUserStatus(
            @PathVariable String uuid,
            @RequestBody @Valid UpdateStatusRequest request) {
        String adminId = adminSecurityService.getCurrentAdminId();
        userService.updateUserStatus(uuid, request.getStatus(), adminId);
        return ResponseEntity.ok(
                ApiResponse.success("User status updated successfully"));
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
            @RequestBody @Valid UpdateRiskRequest request) {
        String adminId = adminSecurityService.getCurrentAdminId();
        userService.updateUserFraudRisk(uuid, request.getRisk(), adminId);
        return ResponseEntity.ok(
                ApiResponse.success("User fraud risk updated successfully"));
    }
}