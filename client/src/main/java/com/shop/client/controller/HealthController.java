package com.shop.client.controller;

import com.shop.client.dto.ApiResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class HealthController {

    @Value("${spring.application.name:client}")
    private String serviceName;

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<Map<String, Object>>> health() {
        Map<String, Object> healthData = new HashMap<>();
        healthData.put("service", serviceName);
        healthData.put("status", "UP");
        
        ApiResponse<Map<String, Object>> response = ApiResponse.success("Service is healthy", healthData);
        return ResponseEntity.ok(response);
    }
}
