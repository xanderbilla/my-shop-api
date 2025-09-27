package com.shop.user.exception;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.shop.user.dto.ApiResponse;
import com.shop.user.enums.CognitoUserStatus;
import com.shop.user.enums.UserRole;
import com.shop.user.enums.FraudRisk;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * Global Exception Handler for User Service
 * 
 * Provides professional error messages for common validation errors
 * including enum deserialization failures and validation constraints
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handle JSON parsing errors, especially enum deserialization failures
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Object>> handleHttpMessageNotReadable(HttpMessageNotReadableException ex) {
        Throwable cause = ex.getCause();

        if (cause instanceof InvalidFormatException) {
            InvalidFormatException ife = (InvalidFormatException) cause;

            // Handle enum deserialization errors
            if (ife.getTargetType().isEnum()) {
                String fieldName = getFieldName(ife);
                String invalidValue = ife.getValue().toString();
                String validValues = getValidEnumValues(ife.getTargetType());

                String message = String.format(
                        "Invalid value '%s' for field '%s'",
                        invalidValue, fieldName);

                // Create error response with accepted values in data field
                EnumValidationError errorData = new EnumValidationError(fieldName, invalidValue, validValues);

                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ApiResponse.error(message, errorData, 400));
            }
        }

        // Generic JSON parsing error
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error("Invalid request format. Please check your JSON structure and data types.",
                        400));
    }

    /**
     * Handle validation errors from @Valid annotations
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Object>> handleValidationErrors(MethodArgumentNotValidException ex) {
        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));

        // Extract field-specific validation errors with accepted values
        ValidationErrorData errorData = new ValidationErrorData();
        ex.getBindingResult().getFieldErrors().forEach(error -> {
            String field = error.getField();
            String message = error.getDefaultMessage();
            if (message.contains("Valid roles are:")) {
                String validValues = Arrays.stream(UserRole.values())
                        .map(Enum::name)
                        .collect(Collectors.joining(", "));
                errorData.addFieldError(field, "At least one role must be specified", validValues);
            } else if (message.contains("Valid statuses are:")) {
                String validValues = Arrays.stream(CognitoUserStatus.values())
                        .map(Enum::name)
                        .collect(Collectors.joining(", "));
                errorData.addFieldError(field, "Status must be specified", validValues);
            } else if (message.contains("Valid risk levels are:")) {
                String validValues = Arrays.stream(FraudRisk.values())
                        .map(Enum::name)
                        .collect(Collectors.joining(", "));
                errorData.addFieldError(field, "Risk level must be specified", validValues);
            } else {
                errorData.addFieldError(field, message, null);
            }
        });

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error("Validation failed", errorData, 400));
    }

    /**
     * Handle illegal argument exceptions
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<String>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(ex.getMessage(), 400));
    }

    /**
     * Handle custom authentication exceptions (user not logged in)
     */
    @ExceptionHandler(UserNotAuthenticatedException.class)
    public ResponseEntity<ApiResponse<String>> handleUserNotAuthenticated(UserNotAuthenticatedException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error(ex.getMessage(), 401));
    }

    /**
     * Handle custom authorization exceptions (user logged in but not admin)
     */
    @ExceptionHandler(AdminAccessDeniedException.class)
    public ResponseEntity<ApiResponse<String>> handleAdminAccessDenied(AdminAccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ApiResponse.error(ex.getMessage(), 403));
    }

    /**
     * Handle method security exceptions (access denied) - fallback
     */
    @ExceptionHandler(org.springframework.security.authorization.AuthorizationDeniedException.class)
    public ResponseEntity<ApiResponse<String>> handleAccessDenied(
            org.springframework.security.authorization.AuthorizationDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ApiResponse.error("Access denied. Only ADMIN users can access this resource.", 403));
    }

    /**
     * Handle authentication exceptions (login required) - fallback
     */
    @ExceptionHandler(org.springframework.security.core.AuthenticationException.class)
    public ResponseEntity<ApiResponse<String>> handleAuthenticationRequired(
            org.springframework.security.core.AuthenticationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error("Please login first to access this resource.", 401));
    }

    /**
     * Handle runtime exceptions
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<String>> handleRuntimeException(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(ex.getMessage(), 400));
    }

    /**
     * Extract field name from JsonMappingException
     */
    private String getFieldName(JsonMappingException ex) {
        return ex.getPath().stream()
                .map(JsonMappingException.Reference::getFieldName)
                .filter(name -> name != null)
                .collect(Collectors.joining("."));
    }

    /**
     * Get valid enum values as a formatted string
     */
    private String getValidEnumValues(Class<?> enumType) {
        if (enumType == CognitoUserStatus.class) {
            return Arrays.stream(CognitoUserStatus.values())
                    .map(Enum::name)
                    .collect(Collectors.joining(", "));
        } else if (enumType == UserRole.class) {
            return Arrays.stream(UserRole.values())
                    .map(Enum::name)
                    .collect(Collectors.joining(", "));
        } else if (enumType == FraudRisk.class) {
            return Arrays.stream(FraudRisk.values())
                    .map(Enum::name)
                    .collect(Collectors.joining(", "));
        } else {
            // Generic enum handling
            return Arrays.stream(enumType.getEnumConstants())
                    .map(Object::toString)
                    .collect(Collectors.joining(", "));
        }
    }

    /**
     * Error data class for enum validation errors
     */
    public static class EnumValidationError {
        private String field;
        private String invalidValue;
        private String acceptedValues;

        public EnumValidationError(String field, String invalidValue, String acceptedValues) {
            this.field = field;
            this.invalidValue = invalidValue;
            this.acceptedValues = acceptedValues;
        }

        public String getField() {
            return field;
        }

        public String getInvalidValue() {
            return invalidValue;
        }

        public String getAcceptedValues() {
            return acceptedValues;
        }
    }

    /**
     * Error data class for validation errors
     */
    public static class ValidationErrorData {
        private java.util.List<FieldError> fieldErrors = new java.util.ArrayList<>();

        public void addFieldError(String field, String message, String acceptedValues) {
            fieldErrors.add(new FieldError(field, message, acceptedValues));
        }

        public java.util.List<FieldError> getFieldErrors() {
            return fieldErrors;
        }

        public static class FieldError {
            private String field;
            private String message;
            private String acceptedValues;

            public FieldError(String field, String message, String acceptedValues) {
                this.field = field;
                this.message = message;
                this.acceptedValues = acceptedValues;
            }

            public String getField() {
                return field;
            }

            public String getMessage() {
                return message;
            }

            public String getAcceptedValues() {
                return acceptedValues;
            }
        }
    }
}