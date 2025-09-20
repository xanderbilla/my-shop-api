package com.shop.auth.controller;

import com.shop.auth.constants.AuthConstants;
import com.shop.auth.dto.*;
import com.shop.auth.enums.UserRole;
import com.shop.auth.model.AuthUser;
import com.shop.auth.service.AuthService;
import com.shop.auth.service.AuthSecurityService;
import com.shop.auth.service.JwtTokenService;
import com.shop.auth.util.CookieUtil;
import com.shop.auth.util.ResponseUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.ArrayList;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtTokenService jwtTokenService;
    private final CookieUtil cookieUtil;
    private final AuthSecurityService authSecurityService;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<AuthUser>> signup(@Valid @RequestBody SignupRequest request) {
        AuthUser user = authService.signup(request);
        return ResponseUtil.created(AuthConstants.SuccessMessages.USER_REGISTERED, user);
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
                AuthConstants.SuccessMessages.USER_SIGNED_IN);

        return ResponseUtil.ok(AuthConstants.SuccessMessages.USER_SIGNED_IN, successResponse);
    }

    @PostMapping("/verify")
    public ResponseEntity<ApiResponse<AuthUser>> verify(@Valid @RequestBody VerifyRequest request) {
        AuthUser user = authService.verify(request);
        return ResponseUtil.ok(AuthConstants.SuccessMessages.EMAIL_VERIFIED, user);
    }

    @GetMapping("/me")
    @PreAuthorize("@authSecurityService.isAuthenticated()")
    public ResponseEntity<ApiResponse<AuthUser>> getCurrentUser(HttpServletRequest request) {
        try {
            // Get token from cookie - @PreAuthorize already validates authentication
            String token = cookieUtil.getAccessTokenFromCookies(request)
                    .orElseThrow(() -> new RuntimeException("Authentication required"));

            // Get user info using the token
            String cognitoUsername = jwtTokenService.extractCognitoUsernameFromToken(token);
            AuthUser user = authService.getUserInfo(cognitoUsername);

            // Extract cognito:groups from JWT token for current roles
            List<String> cognitoGroups = jwtTokenService.extractCognitoGroupsFromToken(token);

            // Convert string groups to UserRole enums
            List<UserRole> roles = new ArrayList<>();
            for (String group : cognitoGroups) {
                try {
                    UserRole role = UserRole.valueOf(group.toUpperCase());
                    roles.add(role);
                } catch (IllegalArgumentException e) {
                    System.err.println("Unknown role from Cognito: " + group);
                }
            }

            // If no valid roles found, default to USER
            if (roles.isEmpty()) {
                roles.add(UserRole.USER);
            }

            user.setRoles(roles);

            return ResponseEntity.ok(ApiResponse.success(
                    "User information retrieved successfully", user));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to get user info: " + e.getMessage()));
        }
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
    @PreAuthorize("@authSecurityService.isAuthenticated()")
    public ResponseEntity<ApiResponse<StatusResponse>> status(HttpServletRequest request) {
        try {
            // Get current user ID from security service
            String userId = authSecurityService.getCurrentUserId();
            
            // Get user info
            AuthUser user = authService.getUserInfo(userId);

            StatusResponse statusResponse = new StatusResponse(
                    user.getStatus() != null ? user.getStatus().toString() : "ACTIVE");

            return ResponseEntity.ok(ApiResponse.success(
                    "User status retrieved successfully", statusResponse));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to get user status: " + e.getMessage()));
        }
    }

    @GetMapping("/roles")
    @PreAuthorize("@authSecurityService.isAuthenticated()")
    public ResponseEntity<ApiResponse<GetRoleResponse>> getUserRoles(HttpServletRequest request) {
        try {
            // Get token from cookie - @PreAuthorize already validates authentication
            String token = cookieUtil.getAccessTokenFromCookies(request)
                    .orElseThrow(() -> new RuntimeException("Authentication required"));

            // Get user info
            String cognitoUsername = jwtTokenService.extractCognitoUsernameFromToken(token);
            AuthUser user = authService.getUserInfo(cognitoUsername);

            // Extract cognito:groups from JWT token for current roles
            List<String> cognitoGroups = jwtTokenService.extractCognitoGroupsFromToken(token);

            // Convert string groups to UserRole enums
            List<UserRole> roles = new ArrayList<>();
            for (String group : cognitoGroups) {
                try {
                    UserRole role = UserRole.valueOf(group.toUpperCase());
                    roles.add(role);
                } catch (IllegalArgumentException e) {
                    System.err.println("Unknown role from Cognito: " + group);
                }
            }

            // If no valid roles found, default to USER
            if (roles.isEmpty()) {
                roles.add(UserRole.USER);
            }

            GetRoleResponse roleResponse = new GetRoleResponse(user.getUsername(), user.getEmail(), roles);

            return ResponseEntity.ok(ApiResponse.success(
                    "User roles retrieved successfully", roleResponse));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to get user roles: " + e.getMessage()));
        }
    }

    @PostMapping("/change-password")
    @PreAuthorize("@authSecurityService.isAuthenticated()")
    public ResponseEntity<ApiResponse<String>> changePassword(
            HttpServletRequest request,
            @Valid @RequestBody ChangePasswordRequest changePasswordRequest) {
        try {
            // Get token from cookie - @PreAuthorize already validates authentication
            String token = cookieUtil.getAccessTokenFromCookies(request)
                    .orElseThrow(() -> new RuntimeException("Authentication required"));

            String cognitoUsername = jwtTokenService.extractCognitoUsernameFromToken(token);

            authService.changePassword(cognitoUsername, 
                    changePasswordRequest.getCurrentPassword(), 
                    changePasswordRequest.getNewPassword());

            return ResponseEntity.ok(ApiResponse.success(
                    "Password changed successfully", "PASSWORD_CHANGED"));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error("Current password is incorrect"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to change password: " + e.getMessage()));
        }
    }
}