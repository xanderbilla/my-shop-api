package com.shop.admin.controller;

import com.shop.admin.dto.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/admin")
public class InfoController {

    @GetMapping("/info")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getAdminInfo() {
        Map<String, Object> data = new HashMap<>();
        data.put("serviceName", "admin");
        data.put("status", "running");
        data.put("description", "Administrative Service");
        
        ApiResponse<Map<String, Object>> response = ApiResponse.success("Admin Service is running", data);
        return ResponseEntity.ok(response);
    }
    
}