package com.shop.auth.util;

import com.shop.auth.dto.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * Utility class for creating consistent API responses
 */
public final class ResponseUtil {

    private ResponseUtil() {
        // Utility class
    }

    /**
     * Create a success response with data
     */
    public static <T> ResponseEntity<ApiResponse<T>> success(String message, T data, HttpStatus status) {
        ApiResponse<T> response = ApiResponse.success(message, data);
        response.setStatus(status.value());
        return ResponseEntity.status(status).body(response);
    }

    /**
     * Create a success response without data
     */
    public static <T> ResponseEntity<ApiResponse<T>> success(String message, HttpStatus status) {
        ApiResponse<T> response = ApiResponse.success(message);
        response.setStatus(status.value());
        return ResponseEntity.status(status).body(response);
    }

    /**
     * Create an error response
     */
    public static <T> ResponseEntity<ApiResponse<T>> error(String message, HttpStatus status) {
        ApiResponse<T> response = ApiResponse.error(message, status.value());
        return ResponseEntity.status(status).body(response);
    }

    /**
     * Create a created response (201)
     */
    public static <T> ResponseEntity<ApiResponse<T>> created(String message, T data) {
        return success(message, data, HttpStatus.CREATED);
    }

    /**
     * Create an OK response (200)
     */
    public static <T> ResponseEntity<ApiResponse<T>> ok(String message, T data) {
        return success(message, data, HttpStatus.OK);
    }

    /**
     * Create an OK response without data (200)
     */
    public static <T> ResponseEntity<ApiResponse<T>> ok(String message) {
        return success(message, HttpStatus.OK);
    }

    /**
     * Create a bad request response (400)
     */
    public static <T> ResponseEntity<ApiResponse<T>> badRequest(String message) {
        return error(message, HttpStatus.BAD_REQUEST);
    }

    /**
     * Create an unauthorized response (401)
     */
    public static <T> ResponseEntity<ApiResponse<T>> unauthorized(String message) {
        return error(message, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Create a forbidden response (403)
     */
    public static <T> ResponseEntity<ApiResponse<T>> forbidden(String message) {
        return error(message, HttpStatus.FORBIDDEN);
    }

    /**
     * Create a not found response (404)
     */
    public static <T> ResponseEntity<ApiResponse<T>> notFound(String message) {
        return error(message, HttpStatus.NOT_FOUND);
    }

    /**
     * Create a conflict response (409)
     */
    public static <T> ResponseEntity<ApiResponse<T>> conflict(String message) {
        return error(message, HttpStatus.CONFLICT);
    }

    /**
     * Create an internal server error response (500)
     */
    public static <T> ResponseEntity<ApiResponse<T>> internalServerError(String message) {
        return error(message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}