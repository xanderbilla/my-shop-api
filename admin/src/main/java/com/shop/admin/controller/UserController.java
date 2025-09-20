package com.shop.admin.controller;

import com.shop.admin.dto.ApiResponse;
import com.shop.admin.model.User;
import com.shop.admin.enums.UserRole;
import com.shop.admin.enums.UserStatus;
import com.shop.admin.enums.FraudRisk;
import com.shop.admin.service.UserService;
import com.shop.admin.service.AdminSecurityService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * REST Controller for User Management operations
 * 
 * 🔒 SECURITY: ALL ENDPOINTS REQUIRE ADMIN AUTHENTICATION via @PreAuthorize
 * 
 * Authentication Requirements:
 * ✅ Valid JWT token in cookies (access_token)
 * ✅ User must be in ADMIN role/group in Cognito
 * ✅ Token validation through AdminSecurityService.isAdmin()
 * ✅ Method-level security with @PreAuthorize annotations
 * 
 * Security Implementation:
 * 1. @PreAuthorize("@adminSecurityService.isAdmin()") - Declarative security
 * 2. AdminSecurityService - Centralized security validation
 * 3. Spring Security - Framework-level security integration
 * 4. HTTP 403 - Automatic access denied response
 * 
 * @author Vikas Singh
 * @version 2.0
 * @since 2025-09-20
 * @created 2025-09-20
 * @lastModified 2025-09-20
 * 
 * @reference Spring Security @PreAuthorize
 * @reference JWT Token Authentication
 * @reference AWS Cognito Integration
 */
@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;
    private final AdminSecurityService adminSecurityService;

    public UserController(UserService userService, AdminSecurityService adminSecurityService) {
        this.userService = userService;
        this.adminSecurityService = adminSecurityService;
    }

    @GetMapping
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<List<User>>> getAllUsers(
            @RequestParam(required = false) Integer limit) {
        try {
            List<User> users;
            if (limit != null && limit > 0) {
                users = userService.getAllUsers(limit);
            } else {
                users = userService.getAllUsers();
            }

            return ResponseEntity.ok(
                    ApiResponse.success("All users retrieved successfully", users));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to retrieve users: " + e.getMessage(), 500));
        }
    }

    @GetMapping("/{uuid}")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> getUserById(@PathVariable String uuid) {
        try {
            Optional<User> user = userService.getUserById(uuid);
            if (user.isPresent()) {
                return ResponseEntity.ok(
                        ApiResponse.success("User retrieved successfully", user.get()));
            } else {
                return ResponseEntity.status(404).body(
                        ApiResponse.error("User not found with UUID: " + uuid, 404));
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to retrieve user: " + e.getMessage(), 500));
        }
    }

    @PostMapping("/add")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<Map<String, String>>> createUser(
            @RequestBody Map<String, String> userCreationRequest) {
        try {
            String email = userCreationRequest.get("email");
            String roleStr = userCreationRequest.get("role");
            String name = userCreationRequest.get("name");

            if (email == null || roleStr == null || name == null) {
                return ResponseEntity.status(400).body(
                        ApiResponse.error("Missing required fields: email, role, name", 400));
            }

            UserRole role = UserRole.valueOf(roleStr.toUpperCase());
            String adminId = adminSecurityService.getCurrentAdminId();

            Map<String, String> result = userService.createUser(email, role, name, adminId);
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

    @DeleteMapping("/{uuid}")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> softDeleteUser(@PathVariable String uuid) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User deletedUser = userService.softDeleteUser(uuid, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User deleted successfully", deletedUser));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to delete user: " + e.getMessage(), 500));
        }
    }

    @PostMapping("/{uuid}/restore")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> restoreUser(@PathVariable String uuid) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User restoredUser = userService.restoreUser(uuid, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User restored successfully", restoredUser));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to restore user: " + e.getMessage(), 500));
        }
    }

    @PutMapping("/{uuid}/address")
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

    @PutMapping("/{uuid}/verify")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> verifyUser(@PathVariable String uuid) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User verifiedUser = userService.verifyUser(uuid, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User verified successfully", verifiedUser));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to verify user: " + e.getMessage(), 500));
        }
    }

    @PutMapping("/{uuid}/role")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> updateUserRole(
            @PathVariable String uuid,
            @RequestParam UserRole role) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User updatedUser = userService.updateUserRole(uuid, role, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User role updated successfully", updatedUser));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to update user role: " + e.getMessage(), 500));
        }
    }

    @PutMapping("/{uuid}/verify-kyc")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> verifyUserKyc(@PathVariable String uuid) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User verifiedUser = userService.verifyUserKyc(uuid, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User KYC verified successfully", verifiedUser));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to verify user KYC: " + e.getMessage(), 500));
        }
    }

    @PutMapping("/{uuid}/status")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> updateUserStatus(
            @PathVariable String uuid,
            @RequestParam UserStatus status) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User updatedUser = userService.updateUserStatus(uuid, status, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User status updated successfully", updatedUser));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to update user status: " + e.getMessage(), 500));
        }
    }

    @PutMapping("/{uuid}/risk")
    @PreAuthorize("@adminSecurityService.isAdmin()")
    public ResponseEntity<ApiResponse<User>> updateUserFraudRisk(
            @PathVariable String uuid,
            @RequestParam FraudRisk risk) {
        try {
            String adminId = adminSecurityService.getCurrentAdminId();
            User updatedUser = userService.updateUserFraudRisk(uuid, risk, adminId);
            return ResponseEntity.ok(
                    ApiResponse.success("User fraud risk updated successfully", updatedUser));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(
                    ApiResponse.error(e.getMessage(), 400));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to update user fraud risk: " + e.getMessage(), 500));
        }
    }
}