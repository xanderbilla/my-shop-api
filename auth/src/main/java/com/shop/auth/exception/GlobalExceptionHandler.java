package com.shop.auth.exception;

import com.shop.auth.dto.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        log.warn("Validation failed: {}", errors);

        ApiResponse<Map<String, String>> response = ApiResponse.error(
                "Validation failed",
                HttpStatus.BAD_REQUEST.value());
        response.setData(errors);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Object>> handleJsonParsingException(HttpMessageNotReadableException ex) {
        log.warn("JSON parsing error: {}", ex.getMessage());

        String errorMessage = "Invalid request format";

        // Check if this is a role enum parsing error
        if (ex.getMessage() != null && ex.getMessage().contains("UserRole")) {
            errorMessage = "Invalid role specified. Valid roles are: USER, ADMIN, SUPPORT";
        }

        ApiResponse<Object> response = ApiResponse.error(
                errorMessage,
                HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(CognitoIdentityProviderException.class)
    public ResponseEntity<ApiResponse<Object>> handleCognitoException(CognitoIdentityProviderException ex) {
        log.error("Cognito error: {}", ex.getMessage());

        String errorMessage = ex.awsErrorDetails() != null ? ex.awsErrorDetails().errorMessage() : ex.getMessage();

        HttpStatus status = mapCognitoErrorToHttpStatus(ex.awsErrorDetails().errorCode());

        ApiResponse<Object> response = ApiResponse.error(errorMessage, status.value());
        return ResponseEntity.status(status).body(response);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<Object>> handleRuntimeException(RuntimeException ex) {
        log.error("Runtime error: {}", ex.getMessage());

        ApiResponse<Object> response = ApiResponse.error(
                ex.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR.value());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<ApiResponse<Object>> handleSecurityException(SecurityException ex) {
        log.warn("Security error: {}", ex.getMessage());

        ApiResponse<Object> response = ApiResponse.error(
                ex.getMessage(),
                HttpStatus.FORBIDDEN.value());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Object>> handleGenericException(Exception ex) {
        log.error("Unexpected error: {}", ex.getMessage(), ex);

        ApiResponse<Object> response = ApiResponse.error(
                "An unexpected error occurred",
                HttpStatus.INTERNAL_SERVER_ERROR.value());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    private HttpStatus mapCognitoErrorToHttpStatus(String errorCode) {
        if (errorCode == null) {
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }

        return switch (errorCode) {
            case "UsernameExistsException" -> HttpStatus.CONFLICT;
            case "UserNotFoundException" -> HttpStatus.NOT_FOUND;
            case "NotAuthorizedException" -> HttpStatus.UNAUTHORIZED;
            case "InvalidParameterException", "InvalidPasswordException" -> HttpStatus.BAD_REQUEST;
            case "CodeMismatchException", "ExpiredCodeException" -> HttpStatus.BAD_REQUEST;
            case "TooManyRequestsException" -> HttpStatus.TOO_MANY_REQUESTS;
            case "UserNotConfirmedException" -> HttpStatus.FORBIDDEN;
            default -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
    }
}