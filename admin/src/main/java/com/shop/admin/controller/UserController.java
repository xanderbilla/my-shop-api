package com.shop.admin.controller;

import com.shop.admin.dto.ApiResponse;
import com.shop.admin.model.User;
import com.shop.admin.service.UserService;
import com.shop.admin.service.JwtTokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;
    private final JwtTokenService jwtTokenService;

    public UserController(UserService userService, JwtTokenService jwtTokenService) {
        this.userService = userService;
        this.jwtTokenService = jwtTokenService;
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<User>>> getAllUsers(
            @RequestParam(required = false) Integer limit,
            HttpServletRequest request) {
        try {
            // Extract JWT token from cookies
            String accessToken = extractAccessTokenFromCookies(request);
            if (accessToken == null) {
                return ResponseEntity.status(401).body(
                        ApiResponse.error("Access token not found", 401));
            }

            // Validate token
            if (!jwtTokenService.isValidToken(accessToken)) {
                return ResponseEntity.status(401).body(
                        ApiResponse.error("Invalid access token", 401));
            }

            // Check if user has ADMIN role
            if (!jwtTokenService.isAdmin(accessToken)) {
                return ResponseEntity.status(403).body(
                        ApiResponse.error("Access denied. Admin role required.", 403));
            }

            List<User> users;
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

    private String extractAccessTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("access_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}