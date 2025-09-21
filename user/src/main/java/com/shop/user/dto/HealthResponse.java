package com.shop.user.dto;

/**
 * Response DTO for health check
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-21
 */
public class HealthResponse {

    private String service;
    private String status;

    public HealthResponse() {
    }

    public HealthResponse(String service, String status) {
        this.service = service;
        this.status = status;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @Override
    public String toString() {
        return "HealthResponse{" +
                "service='" + service + '\'' +
                ", status='" + status + '\'' +
                '}';
    }
}