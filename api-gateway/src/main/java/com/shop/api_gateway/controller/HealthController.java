package com.shop.api_gateway.controller;

import com.shop.api_gateway.dto.ApiResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class HealthController {

    @Value("${spring.application.name}")
    private String applicationName;

    @GetMapping("/health")
    public ApiResponse<Map<String, Object>> health() {
        Map<String, Object> healthData = new HashMap<>();
        healthData.put("service", applicationName);
        healthData.put("status", "UP");
        
        return ApiResponse.success("API Gateway is healthy", healthData);
    }

    @GetMapping("/info")
    public ApiResponse<Map<String, Object>> info() {
        Map<String, Object> infoData = new HashMap<>();
        infoData.put("service", applicationName);
        infoData.put("version", "1.0.0");
        infoData.put("type", "API Gateway");
        infoData.put("description", "Spring Cloud Gateway for routing requests to microservices");
        infoData.put("features", new String[]{
            "Service Discovery with Eureka",
            "Load Balancing",
            "CORS Support",
            "Route Management",
            "Health Monitoring"
        });
        
        return ApiResponse.success("API Gateway service information", infoData);
    }
}
