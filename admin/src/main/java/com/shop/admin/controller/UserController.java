package com.shop.admin.controller;

import com.shop.admin.dto.ApiResponse;
import com.shop.admin.model.AdminUserProfile;
import com.shop.admin.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<AdminUserProfile>>> getAllUsers(
            @RequestParam(required = false) Integer limit) {
        try {
            List<AdminUserProfile> users;
            if (limit != null && limit > 0) {
                users = userService.getAllUsers(limit);
            } else {
                users = userService.getAllUsers(); // Get all users if no limit specified
            }

            String message = limit != null
                    ? String.format("Users retrieved successfully (limit: %d)", limit)
                    : "All users retrieved successfully";

            return ResponseEntity.ok(
                    ApiResponse.success(message, users));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                    ApiResponse.error("Failed to retrieve users: " + e.getMessage(), 500));
        }
    }
}