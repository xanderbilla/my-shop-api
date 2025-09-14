package com.shop.auth.controller;

import com.shop.auth.dto.*;
import com.shop.auth.exception.InvalidTokenException;
import com.shop.auth.model.User;
import com.shop.auth.service.AuthService;
import com.shop.auth.service.JwtTokenService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final JwtTokenService jwtTokenService;

    // Constructor for dependency injection
    public AuthController(AuthService authService, JwtTokenService jwtTokenService) {
        this.authService = authService;
        this.jwtTokenService = jwtTokenService;
    }

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<User>> signup(@Valid @RequestBody SignupRequest request) {
        log.info("Signup request received for username: {}", request.getUsername());
        User user = authService.signup(request);

        ApiResponse<User> response = ApiResponse.success(
                "User registered successfully. Please check your email for verification code.",
                user);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/signin")
    public ResponseEntity<ApiResponse<AuthResponse>> signin(@Valid @RequestBody SigninRequest request) {
        log.info("Signin request received for username: {}", request.getUsername());
        AuthResponse authResponse = authService.signin(request);

        ApiResponse<AuthResponse> response = ApiResponse.success(
                "User signed in successfully",
                authResponse);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    public ResponseEntity<ApiResponse<User>> verify(@Valid @RequestBody VerifyRequest request) {
        log.info("Verification request received for username: {}", request.getUsername());
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
            // Extract email from JWT token (Cognito uses email as username)
            String email = jwtTokenService.extractEmailFromToken(token);
            log.info("Get current user request for email: {}", email);

            // Find the actual Cognito username based on email and get user info
            User user = authService.getUserInfoByEmail(email);

            ApiResponse<User> response = ApiResponse.success(
                    "User information retrieved successfully",
                    user);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error getting current user from token: {}", e.getMessage());
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

        log.info("Logout request received");

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
        log.info("Forgot password request received for email: {}", request.getEmail());
        authService.forgotPassword(request.getEmail());

        ApiResponse<String> response = ApiResponse.success(
                "Password reset code sent to your email",
                "CODE_SENT");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<String>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        log.info("Reset password request received for email: {}", request.getEmail());
        authService.resetPassword(request.getEmail(), request.getVerificationCode(), request.getNewPassword());

        ApiResponse<String> response = ApiResponse.success(
                "Password reset successfully",
                "PASSWORD_RESET");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<ApiResponse<String>> resendOtp(@Valid @RequestBody ResendOtpRequest request) {
        log.info("Resend OTP request received for email: {}", request.getEmail());
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
}