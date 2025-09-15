package com.shop.auth.controller;

import com.shop.auth.dto.*;
import com.shop.auth.exception.InvalidTokenException;
import com.shop.auth.model.User;
import com.shop.auth.service.AuthService;
import com.shop.auth.service.JwtTokenService;
import com.shop.auth.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
    private final CookieUtil cookieUtil;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<User>> signup(@Valid @RequestBody SignupRequest request) {
        User user = authService.signup(request);

        ApiResponse<User> response = ApiResponse.success(
                "User registered successfully. Please check your email for verification code.",
                user);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/signin")
    public ResponseEntity<ApiResponse<AuthSuccessResponse>> signin(
            @Valid @RequestBody SigninRequest request,
            HttpServletResponse response) {
        AuthResponse authResponse = authService.signin(request);

        // Set tokens in HTTP-only cookies
        cookieUtil.setAccessTokenCookie(response, authResponse.getAccessToken());
        cookieUtil.setRefreshTokenCookie(response, authResponse.getRefreshToken());

        // Return success response without tokens
        AuthSuccessResponse successResponse = AuthSuccessResponse.success(
                authResponse.getUser(),
                "User signed in successfully");

        ApiResponse<AuthSuccessResponse> response_ = ApiResponse.success(
                "User signed in successfully",
                successResponse);
        return ResponseEntity.ok(response_);
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
    public ResponseEntity<ApiResponse<User>> getCurrentUser(HttpServletRequest request) {
        // Get token from cookie instead of Authorization header
        String token = cookieUtil.getAccessTokenFromCookies(request)
                .orElseThrow(() -> new RuntimeException("Authentication required"));

        User user = validateTokenAndGetUser("Bearer " + token);

        ApiResponse<User> response = ApiResponse.success(
                "User information retrieved successfully",
                user);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Get token from cookie for Cognito logout
            String token = cookieUtil.getAccessTokenFromCookies(request).orElse(null);

            if (token != null) {
                // Logout from Cognito
                authService.logout(token);

                // Blacklist the token
                jwtTokenService.blacklistToken(token);
            }

            // Clear authentication cookies
            cookieUtil.clearAuthCookies(response);

            ApiResponse<String> apiResponse = ApiResponse.success(
                    "User logged out successfully",
                    "LOGGED_OUT");
            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            // Even if logout fails, clear cookies
            cookieUtil.clearAuthCookies(response);

            ApiResponse<String> apiResponse = ApiResponse.success(
                    "Logged out successfully",
                    "LOGGED_OUT");
            return ResponseEntity.ok(apiResponse);
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<String>> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Get both access and refresh tokens from cookies
            String refreshToken = cookieUtil.getRefreshTokenFromCookies(request)
                    .orElseThrow(() -> new RuntimeException("Refresh token not found"));

            String accessToken = cookieUtil.getAccessTokenFromCookies(request)
                    .orElseThrow(() -> new RuntimeException("Access token not found"));

            // Extract username from access token for secret hash calculation
            String username = jwtTokenService.extractUsernameFromToken(accessToken);

            // Call auth service to refresh tokens
            AuthResponse authResponse = authService.refreshToken(refreshToken, username);

            // Set new tokens in cookies
            cookieUtil.setAccessTokenCookie(response, authResponse.getAccessToken());
            if (authResponse.getRefreshToken() != null) {
                cookieUtil.setRefreshTokenCookie(response, authResponse.getRefreshToken());
            }

            // Return success response
            ApiResponse<String> apiResponse = ApiResponse.success(
                    "Token refreshed successfully",
                    "TOKEN_REFRESHED");
            return ResponseEntity.ok(apiResponse);

        } catch (Exception e) {
            // Clear cookies on refresh failure
            cookieUtil.clearAuthCookies(response);

            ApiResponse<String> apiResponse = ApiResponse.error("Failed to refresh token: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(apiResponse);
        }
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
    public ResponseEntity<ApiResponse<GetRoleResponse>> getUserRoles(HttpServletRequest request) {
        try {
            // Get token from cookie instead of Authorization header
            String token = cookieUtil.getAccessTokenFromCookies(request)
                    .orElseThrow(() -> new RuntimeException("Authentication required"));

            User user = validateTokenAndGetUser("Bearer " + token);
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
            HttpServletRequest request,
            @Valid @RequestBody ChangePasswordRequest request1) {
        try {
            // Get token from cookie instead of Authorization header
            String token = cookieUtil.getAccessTokenFromCookies(request)
                    .orElseThrow(() -> new RuntimeException("Authentication required"));

            String cognitoUsername = jwtTokenService.extractCognitoUsernameFromToken(token);

            authService.changePassword(cognitoUsername, request1.getCurrentPassword(), request1.getNewPassword());

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