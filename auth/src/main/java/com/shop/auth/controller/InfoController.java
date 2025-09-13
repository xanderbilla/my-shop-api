package com.shop.auth.controller;

import com.shop.auth.dto.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class InfoController {

    @GetMapping("/info")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getAuthInfo() {
        Map<String, Object> data = new HashMap<>();
        data.put("serviceName", "auth");
        data.put("status", "running");
        data.put("description", "Authentication Service");
        
        ApiResponse<Map<String, Object>> response = ApiResponse.success("Auth Service is running", data);
        return ResponseEntity.ok(response);
    }
    
}