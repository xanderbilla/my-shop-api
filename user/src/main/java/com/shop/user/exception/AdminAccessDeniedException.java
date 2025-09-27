package com.shop.user.exception;

/**
 * Exception thrown when user is authenticated but not authorized for admin
 * access
 */
public class AdminAccessDeniedException extends RuntimeException {
    public AdminAccessDeniedException(String message) {
        super(message);
    }
}