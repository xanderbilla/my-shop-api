package com.shop.carousel.controller;

import com.shop.carousel.dto.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/carousel")
@Slf4j
@CrossOrigin(origins = "*")
public class HealthController {

    /**
     * Health check endpoint for carousel service
     */
    @GetMapping("/health")
    public ResponseEntity<ApiResponse<Map<String, Object>>> healthCheck() {
        log.info("GET /carousel/health - Health check requested");

        Map<String, Object> healthData = Map.of(
                "service", "carousel-service",
                "status", "UP",
                "port", 8087,
                "contextPath", "/api/v1");

        return ResponseEntity.ok(
                ApiResponse.success("Carousel service is running", healthData));
    }
}