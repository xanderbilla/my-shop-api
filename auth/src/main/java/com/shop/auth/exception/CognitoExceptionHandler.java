package com.shop.auth.exception;

import com.shop.auth.constants.AuthConstants;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;

/**
 * Utility class for handling AWS Cognito exceptions consistently
 */
@Slf4j
public final class CognitoExceptionHandler {

    private CognitoExceptionHandler() {
        // Utility class
    }

    /**
     * Handle Cognito exceptions and throw appropriate runtime exceptions
     */
    public static void handleCognitoException(CognitoIdentityProviderException e, String operation) {
        String errorCode = e.awsErrorDetails() != null ? e.awsErrorDetails().errorCode() : "UNKNOWN";
        String errorMessage = e.awsErrorDetails() != null ? e.awsErrorDetails().errorMessage() : e.getMessage();

        log.error("Cognito error during {}: {} - {}", operation, errorCode, errorMessage);

        switch (errorCode) {
            case AuthConstants.CognitoErrorCodes.USERNAME_EXISTS ->
                throw new UserAlreadyExistsException("User already exists with this email");
            case AuthConstants.CognitoErrorCodes.USER_NOT_FOUND ->
                throw new UserNotFoundException(AuthConstants.ErrorMessages.USER_NOT_FOUND);
            case AuthConstants.CognitoErrorCodes.NOT_AUTHORIZED ->
                throw new AuthenticationException(AuthConstants.ErrorMessages.INVALID_CREDENTIALS);
            case AuthConstants.CognitoErrorCodes.INVALID_PARAMETER,
                    AuthConstants.CognitoErrorCodes.INVALID_PASSWORD ->
                throw new IllegalArgumentException(errorMessage);
            case AuthConstants.CognitoErrorCodes.CODE_MISMATCH,
                    AuthConstants.CognitoErrorCodes.EXPIRED_CODE ->
                throw new VerificationException(AuthConstants.ErrorMessages.VERIFICATION_FAILED);
            case AuthConstants.CognitoErrorCodes.USER_NOT_CONFIRMED ->
                throw new VerificationException("User email is not verified");
            default -> {
                log.error("Unhandled Cognito error: {} - {}", errorCode, errorMessage);
                throw new RuntimeException(operation + " failed: " + errorMessage);
            }
        }
    }

    /**
     * Handle generic exception during Cognito operations
     */
    public static void handleGenericException(Exception e, String operation) {
        log.error("Error during {}: {}", operation, e.getMessage(), e);
        throw new RuntimeException(operation + " failed: " + e.getMessage(), e);
    }
}