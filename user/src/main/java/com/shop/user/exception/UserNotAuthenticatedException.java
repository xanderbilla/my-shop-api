package com.shop.user.exception;

/**
 * Exception thrown when user is not authenticated (no token or invalid token)
 */
public class UserNotAuthenticatedException extends RuntimeException {
    public UserNotAuthenticatedException(String message) {
        super(message);
    }
}