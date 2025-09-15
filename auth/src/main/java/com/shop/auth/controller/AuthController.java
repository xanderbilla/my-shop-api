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

        User user = validateTokenAndGetUser(authHeader);

        ApiResponse<User> response = ApiResponse.success(
                "User information retrieved successfully",
                user);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        String token = validateAndExtractToken(authHeader);

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

    @GetMapping("/status")
    public ResponseEntity<ApiResponse<StatusResponse>> status(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        User user = validateTokenAndGetUser(authHeader);

        StatusResponse statusResponse = new StatusResponse(
                user.getStatus() != null ? user.getStatus().toString() : "ACTIVE");

        ApiResponse<StatusResponse> response = ApiResponse.success(
                "User status retrieved successfully",
                statusResponse);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/roles")
    public ResponseEntity<ApiResponse<GetRoleResponse>> getUserRoles(
            @RequestHeader("Authorization") String authorizationHeader) {
        try {
            User user = validateTokenAndGetUser(authorizationHeader);
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

    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<String>> changePassword(
            @RequestHeader("Authorization") String authorizationHeader,
            @Valid @RequestBody ChangePasswordRequest request) {
        try {
            String token = validateAndExtractToken(authorizationHeader);
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

    // ===============================
    // UTILITY METHODS (Reusable)
    // ===============================

    /**
     * Validates authorization header and extracts JWT token
     * 
     * @param authHeader Authorization header from request
     * @return Validated JWT token
     * @throws InvalidTokenException if token is invalid or missing
     */
    private String validateAndExtractToken(String authHeader) {
        if (authHeader == null || authHeader.trim().isEmpty()) {
            throw new InvalidTokenException("Authorization header is required");
        }

        String token = jwtTokenService.extractTokenFromHeader(authHeader);
        if (token == null || !jwtTokenService.isValidToken(token)) {
            throw new InvalidTokenException("Invalid or expired token");
        }

        return token;
    }

    /**
     * Extracts Cognito username from JWT token and retrieves user info
     * 
     * @param token Validated JWT token
     * @return User object with complete information
     * @throws InvalidTokenException if user extraction fails
     */
    private User extractUserFromToken(String token) {
        try {
            String cognitoUsername = jwtTokenService.extractCognitoUsernameFromToken(token);
            return authService.getUserInfo(cognitoUsername);
        } catch (Exception e) {
            throw new InvalidTokenException("Failed to extract user information from token");
        }
    }

    /**
     * Complete token validation and user extraction in one step
     * 
     * @param authHeader Authorization header from request
     * @return User object with complete information
     * @throws InvalidTokenException if validation fails
     */
    private User validateTokenAndGetUser(String authHeader) {
        String token = validateAndExtractToken(authHeader);
        return extractUserFromToken(token);
    }
}