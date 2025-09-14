package com.shop.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {
    private String message;
    private T data;
    private boolean success;
    private int status;
    private String timestamp;

    // Default constructor
    public ApiResponse() {
    }

    // All-args constructor
    public ApiResponse(String message, T data, boolean success, int status, String timestamp) {
        this.message = message;
        this.data = data;
        this.success = success;
        this.status = status;
        this.timestamp = timestamp;
    }

    public ApiResponse(String message, boolean success, int status) {
        this.message = message;
        this.success = success;
        this.status = status;
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
    }

    public ApiResponse(String message, T data, boolean success, int status) {
        this.message = message;
        this.data = data;
        this.success = success;
        this.status = status;
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
    }

    // Getters
    public String getMessage() {
        return message;
    }

    public T getData() {
        return data;
    }

    public boolean isSuccess() {
        return success;
    }

    public int getStatus() {
        return status;
    }

    public String getTimestamp() {
        return timestamp;
    }

    // Setters
    public void setMessage(String message) {
        this.message = message;
    }

    public void setData(T data) {
        this.data = data;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    // Static factory methods for common responses
    public static <T> ApiResponse<T> success(String message) {
        return new ApiResponse<>(message, true, 200);
    }

    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(message, data, true, 200);
    }

    public static <T> ApiResponse<T> error(String message, int status) {
        return new ApiResponse<>(message, false, status);
    }

    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>(message, false, 500);
    }
}
