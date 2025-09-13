package com.shop.admin.dto;

import java.time.LocalDateTime;
import java.util.Map;

public class HealthInfo {
    private String serviceName;
    private String status;
    private String version;
    private LocalDateTime uptime;
    private Map<String, Object> details;

    public HealthInfo() {}

    public HealthInfo(String serviceName, String status, String version, LocalDateTime uptime) {
        this.serviceName = serviceName;
        this.status = status;
        this.version = version;
        this.uptime = uptime;
    }

    // Getters and Setters
    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public LocalDateTime getUptime() {
        return uptime;
    }

    public void setUptime(LocalDateTime uptime) {
        this.uptime = uptime;
    }

    public Map<String, Object> getDetails() {
        return details;
    }

    public void setDetails(Map<String, Object> details) {
        this.details = details;
    }
}
