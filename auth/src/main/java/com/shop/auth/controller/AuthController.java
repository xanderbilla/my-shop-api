package com.shop.auth.controller;

import com.shop.auth.dto.*;
import com.shop.auth.exception.InvalidTokenException;
import com.shop.auth.model.User;
import com.shop.auth.service.AuthService;
import com.shop.auth.service.JwtTokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtTokenService jwtTokenService;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<User>> signup(@Valid @RequestBody SignupRequest request) {
        User user = authService.signup(request);

        ApiResponse<User> response = ApiResponse.success(
                "User registered successfully. Please check your email for verification code.",
                user);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/signin")
    public ResponseEntity<ApiResponse<AuthResponse>> signin(@Valid @RequestBody SigninRequest request) {
        AuthResponse authResponse = authService.signin(request);

        ApiResponse<AuthResponse> response = ApiResponse.success(
                "User signed in successfully",
                authResponse);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    public ResponseEntity<ApiResponse<User>> verify(@Valid @RequestBody VerifyRequest request) {
        User user = authService.verify(request);

        ApiResponse<User> response = ApiResponse.success(
                "User verified successfully",
                user);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<User>> getCurrentUser(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        // Check if Authorization header is present
        if (authHeader == null || authHeader.trim().isEmpty()) {
            throw new InvalidTokenException("Authorization header is required");
        }

        // Extract and validate token
        String token = jwtTokenService.extractTokenFromHeader(authHeader);
        if (token == null || !jwtTokenService.isValidToken(token)) {
            throw new InvalidTokenException("Invalid or expired token");
        }

        try {
            // Extract Cognito username (UUID) from JWT token
            String cognitoUsername = jwtTokenService.extractCognitoUsernameFromToken(token);

            // Get user info using the Cognito username
            User user = authService.getUserInfo(cognitoUsername);

            ApiResponse<User> response = ApiResponse.success(
                    "User information retrieved successfully",
                    user);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            throw new InvalidTokenException("Failed to extract user information from token");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        // Check if Authorization header is present
        if (authHeader == null || authHeader.trim().isEmpty()) {
            throw new InvalidTokenException("Authorization header is required");
        }

        // Extract and validate token
        String token = jwtTokenService.extractTokenFromHeader(authHeader);
        if (token == null || !jwtTokenService.isValidToken(token)) {
            throw new InvalidTokenException("Invalid or expired token");
        }

        // Logout from Cognito
        authService.logout(token);

        // Blacklist the token
        jwtTokenService.blacklistToken(token);

        ApiResponse<String> response = ApiResponse.success(
                "User logged out successfully",
                "LOGGED_OUT");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.forgotPassword(request.getEmail());

        ApiResponse<String> response = ApiResponse.success(
                "Password reset code sent to your email",
                "CODE_SENT");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<String>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.getEmail(), request.getVerificationCode(), request.getNewPassword());

        ApiResponse<String> response = ApiResponse.success(
                "Password reset successfully",
                "PASSWORD_RESET");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<ApiResponse<String>> resendOtp(@Valid @RequestBody ResendOtpRequest request) {
        authService.resendVerificationCode(request.getEmail());

        ApiResponse<String> response = ApiResponse.success(
                "Verification code resent to your email",
                "CODE_SENT");
        return ResponseEntity.ok(response);
    }

    // Health check endpoint for the auth controller
    @GetMapping("/status")
    public ResponseEntity<ApiResponse<String>> status() {
        ApiResponse<String> response = ApiResponse.success(
                "Auth service is running",
                "ACTIVE");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/roles")
    public ResponseEntity<ApiResponse<GetRoleResponse>> getUserRoles(
            @RequestHeader("Authorization") String authorizationHeader) {
        try {
            String token = authorizationHeader.replace("Bearer ", "");
            String cognitoUsername = jwtTokenService.extractCognitoUsernameFromToken(token);

            User user = authService.getUserInfo(cognitoUsername);
            GetRoleResponse roleResponse = new GetRoleResponse(user.getUsername(), user.getEmail(), user.getRoles());

            ApiResponse<GetRoleResponse> response = ApiResponse.success(
                    "User roles retrieved successfully",
                    roleResponse);
            return ResponseEntity.ok(response);
        } catch (InvalidTokenException e) {
            ApiResponse<GetRoleResponse> response = ApiResponse.error("Invalid token: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        } catch (Exception e) {
            ApiResponse<GetRoleResponse> response = ApiResponse.error("Failed to get user roles: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @PutMapping("/roles")
    public ResponseEntity<ApiResponse<String>> updateUserRoles(
            @RequestHeader("Authorization") String authorizationHeader,
            @Valid @RequestBody UpdateRoleRequest request) {
        try {
            String token = authorizationHeader.replace("Bearer ", "");
            String requesterCognitoUsername = jwtTokenService.extractCognitoUsernameFromToken(token);

            // For now, assume the username is an email (we can enhance this later)
            String targetUserEmail = request.getUsername();
            if (!targetUserEmail.contains("@")) {
                // If it's not an email, try to find the email by username
                targetUserEmail = authService.findEmailByCustomUsername(request.getUsername());
                if (targetUserEmail == null) {
                    throw new RuntimeException("User not found with username: " + request.getUsername());
                }
            }

            authService.updateUserRoles(targetUserEmail, request.getRoles(), requesterCognitoUsername);

            ApiResponse<String> response = ApiResponse.success(
                    "User roles updated successfully",
                    "ROLES_UPDATED");
            return ResponseEntity.ok(response);
        } catch (SecurityException e) {
            ApiResponse<String> response = ApiResponse.error("Access denied: " + e.getMessage(),
                    HttpStatus.FORBIDDEN.value());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        } catch (InvalidTokenException e) {
            ApiResponse<String> response = ApiResponse.error("Invalid token: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        } catch (Exception e) {
            ApiResponse<String> response = ApiResponse.error("Failed to update user roles: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<String>> changePassword(
            @RequestHeader("Authorization") String authorizationHeader,
            @Valid @RequestBody ChangePasswordRequest request) {
        try {
            String token = authorizationHeader.replace("Bearer ", "");
            String cognitoUsername = jwtTokenService.extractCognitoUsernameFromToken(token);

            authService.changePassword(cognitoUsername, request.getCurrentPassword(), request.getNewPassword());

            ApiResponse<String> response = ApiResponse.success(
                    "Password changed successfully",
                    "PASSWORD_CHANGED");
            return ResponseEntity.ok(response);
        } catch (SecurityException e) {
            ApiResponse<String> response = ApiResponse.error("Current password is incorrect");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        } catch (InvalidTokenException e) {
            ApiResponse<String> response = ApiResponse.error("Invalid token: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        } catch (Exception e) {
            ApiResponse<String> response = ApiResponse.error("Failed to change password: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}