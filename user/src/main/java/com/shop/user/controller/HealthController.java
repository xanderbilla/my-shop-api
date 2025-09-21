package com.shop.user.controller;

import com.shop.user.dto.ApiResponse;
import com.shop.user.dto.HealthResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class HealthController {

    @Value("${spring.application.name:user}")
    private String serviceName;

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<HealthResponse>> health() {
        HealthResponse healthData = new HealthResponse(serviceName, "UP");

        ApiResponse<HealthResponse> response = ApiResponse.success("Service is healthy", healthData);
        return ResponseEntity.ok(response);
    }
}