package com.shop.client.controller;

import com.shop.client.dto.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/client")
public class InfoController {

    @GetMapping("/info")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getClientInfo() {
        Map<String, Object> data = new HashMap<>();
        data.put("serviceName", "client");
        data.put("status", "running");
        data.put("description", "Client Service");
        
        ApiResponse<Map<String, Object>> response = ApiResponse.success("Client Service is running", data);
        return ResponseEntity.ok(response);
    }
    
}