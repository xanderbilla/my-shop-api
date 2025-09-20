package com.shop.auth.controller;

import com.shop.auth.constants.AuthConstants;
import com.shop.auth.dto.ApiResponse;
import com.shop.auth.util.ResponseUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class HealthController {

    @Value("${spring.application.name:auth}")
    private String serviceName;

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<Map<String, Object>>> health() {
        Map<String, Object> healthData = new HashMap<>();
        healthData.put("service", serviceName);
        healthData.put("status", "UP");

        return ResponseUtil.ok(AuthConstants.StatusMessages.HEALTH_OK, healthData);
    }
}
