package com.shop.client.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {
    private String message;
    private T data;
    private boolean success;
    private int status;
    private LocalDateTime timestamp;

    public ApiResponse(String message, boolean success, int status) {
        this.message = message;
        this.success = success;
        this.status = status;
        this.timestamp = LocalDateTime.now();
    }

    public ApiResponse(String message, T data, boolean success, int status) {
        this.message = message;
        this.data = data;
        this.success = success;
        this.status = status;
        this.timestamp = LocalDateTime.now();
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
