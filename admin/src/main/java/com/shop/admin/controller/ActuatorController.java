package com.shop.admin.controller;

import com.shop.admin.dto.ApiResponse;
import com.shop.admin.dto.HealthInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/admin/actuator")
public class ActuatorController {

    @Value("${spring.application.name:admin}")
    private String serviceName;

    private final LocalDateTime startTime = LocalDateTime.now();

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<HealthInfo>> health() {
        HealthInfo healthInfo = new HealthInfo();
        healthInfo.setServiceName(serviceName);
        healthInfo.setStatus("UP");
        healthInfo.setVersion("1.0.0");
        healthInfo.setUptime(startTime);
        
        Map<String, Object> details = new HashMap<>();
        details.put("diskSpace", "Available");
        details.put("database", "Connected");
        details.put("memory", "Healthy");
        healthInfo.setDetails(details);

        ApiResponse<HealthInfo> response = ApiResponse.success("Service is healthy", healthInfo);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/info")
    public ResponseEntity<ApiResponse<Map<String, Object>>> info() {
        Map<String, Object> info = new HashMap<>();
        info.put("serviceName", serviceName);
        info.put("description", "Administrative Service");
        info.put("version", "1.0.0");
        info.put("environment", "development");
        info.put("startTime", startTime);
        info.put("javaVersion", System.getProperty("java.version"));
        info.put("springBootVersion", "3.5.5");

        ApiResponse<Map<String, Object>> response = ApiResponse.success("Service information retrieved successfully", info);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/metrics")
    public ResponseEntity<ApiResponse<Map<String, Object>>> metrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        Runtime runtime = Runtime.getRuntime();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long usedMemory = totalMemory - freeMemory;
        
        metrics.put("memory.total", totalMemory / (1024 * 1024) + " MB");
        metrics.put("memory.used", usedMemory / (1024 * 1024) + " MB");
        metrics.put("memory.free", freeMemory / (1024 * 1024) + " MB");
        metrics.put("processors", runtime.availableProcessors());
        metrics.put("uptime", "Since " + startTime);

        ApiResponse<Map<String, Object>> response = ApiResponse.success("Metrics retrieved successfully", metrics);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/env")
    public ResponseEntity<ApiResponse<Map<String, Object>>> environment() {
        Map<String, Object> env = new HashMap<>();
        env.put("active.profiles", System.getProperty("spring.profiles.active", "default"));
        env.put("java.version", System.getProperty("java.version"));
        env.put("java.vendor", System.getProperty("java.vendor"));
        env.put("os.name", System.getProperty("os.name"));
        env.put("os.version", System.getProperty("os.version"));
        env.put("user.timezone", System.getProperty("user.timezone"));

        ApiResponse<Map<String, Object>> response = ApiResponse.success("Environment information retrieved successfully", env);
        return ResponseEntity.ok(response);
    }
}
