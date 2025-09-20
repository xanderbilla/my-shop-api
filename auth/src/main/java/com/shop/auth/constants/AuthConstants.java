package com.shop.auth.constants;

/**
 * Central constants for the authentication module
 */
public final class AuthConstants {

    private AuthConstants() {
        // Utility class
    }

    // Error Messages
    public static final class ErrorMessages {
        public static final String USER_NOT_FOUND = "User not found";
        public static final String INVALID_CREDENTIALS = "Invalid credentials provided";
        public static final String VERIFICATION_FAILED = "Email verification failed";
        public static final String TOKEN_EXPIRED = "Token has expired";
        public static final String INVALID_TOKEN = "Invalid or malformed token";
        public static final String AUTHORIZATION_REQUIRED = "Authorization header is required";
        public static final String FAILED_TO_EXTRACT_USER_INFO = "Failed to extract user information from token";
        public static final String AUTHENTICATION_CHALLENGE_REQUIRED = "Authentication challenge required";
        public static final String ONLY_ADMIN_CAN_UPDATE_ROLES = "Only ADMIN users can update roles";
        public static final String USER_ALREADY_DELETED = "User is already deleted";
        public static final String USER_NOT_DELETED = "User is not deleted";
        public static final String USERNAME_EMAIL_NOT_FOUND_IN_TOKEN = "Username/email not found in token";
        public static final String CUSTOM_USERNAME_NOT_FOUND = "Custom username not found in token";
        public static final String INVALID_JWT_FORMAT = "Invalid JWT token format";
        public static final String INVALID_REQUEST_FORMAT = "Invalid request format";
        public static final String INVALID_ROLE_SPECIFIED = "Invalid role specified. Valid roles are: USER, ADMIN, SUPPORT";
        public static final String VALIDATION_FAILED = "Validation failed";
        public static final String UNEXPECTED_ERROR = "An unexpected error occurred";
    }

    // Success Messages
    public static final class SuccessMessages {
        public static final String USER_REGISTERED = "User registered successfully. Please check your email for verification code.";
        public static final String USER_SIGNED_IN = "User signed in successfully";
        public static final String EMAIL_VERIFIED = "Email verified successfully";
        public static final String PASSWORD_RESET_CODE_SENT = "Password reset code sent to your email";
        public static final String PASSWORD_RESET_SUCCESS = "Password reset successful";
        public static final String VERIFICATION_CODE_RESENT = "Verification code resent successfully";
        public static final String USER_LOGGED_OUT = "User logged out successfully";
        public static final String ROLE_UPDATED = "User role updated successfully";
        public static final String USER_DELETED = "User deleted successfully";
        public static final String USER_RESTORED = "User restored successfully";
    }

    // AWS Cognito Error Codes
    public static final class CognitoErrorCodes {
        public static final String USERNAME_EXISTS = "UsernameExistsException";
        public static final String USER_NOT_FOUND = "UserNotFoundException";
        public static final String NOT_AUTHORIZED = "NotAuthorizedException";
        public static final String INVALID_PARAMETER = "InvalidParameterException";
        public static final String INVALID_PASSWORD = "InvalidPasswordException";
        public static final String CODE_MISMATCH = "CodeMismatchException";
        public static final String EXPIRED_CODE = "ExpiredCodeException";
        public static final String TOO_MANY_REQUESTS = "TooManyRequestsException";
        public static final String USER_NOT_CONFIRMED = "UserNotConfirmedException";
    }

    // AWS Cognito Attributes
    public static final class CognitoAttributes {
        public static final String EMAIL = "email";
        public static final String NAME = "name";
        public static final String CUSTOM_ROLE = "custom:role";
        public static final String CUSTOM_USERNAME = "custom:username";
    }

    // JWT Claims
    public static final class JwtClaims {
        public static final String COGNITO_GROUPS = "cognito:groups";
        public static final String USERNAME = "username";
        public static final String EMAIL = "email";
        public static final String CUSTOM_USERNAME = "custom:username";
    }

    // HTTP Status Messages
    public static final class StatusMessages {
        public static final String HEALTH_OK = "Auth service is running";
    }
}