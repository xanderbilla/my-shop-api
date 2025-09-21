package com.shop.carousel.controller;

import com.shop.carousel.model.AdminCarousel;
import com.shop.carousel.service.CarouselService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/admin/carousels")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "*") // Allow cross-origin for easy testing
public class CarouselController {

        private final CarouselService carouselService;

        /**
         * GET /admin/carousels - List all carousels
         * GET /admin/carousels?type=homepage - Filter by placement type
         * GET /admin/carousels?status=active - Filter by status
         */
        @GetMapping
        public ResponseEntity<Map<String, Object>> getAllCarousels(
                        @RequestParam(required = false) String type,
                        @RequestParam(required = false) String status) {

                log.info("GET /admin/carousels - type: {}, status: {}", type, status);

                try {
                        List<AdminCarousel> carousels;

                        if (type != null && !type.isEmpty()) {
                                carousels = carouselService.getCarouselsByType(type);
                        } else if (status != null && !status.isEmpty()) {
                                carousels = carouselService.getCarouselsByStatus(status);
                        } else {
                                carousels = carouselService.getAllCarousels();
                        }

                        return ResponseEntity.ok(Map.of(
                                        "success", true,
                                        "message", "Carousels retrieved successfully",
                                        "data", carousels,
                                        "count", carousels.size()));
                } catch (Exception e) {
                        log.error("Error retrieving carousels", e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(Map.of(
                                                        "success", false,
                                                        "message", "Failed to retrieve carousels: " + e.getMessage()));
                }
        }

        /**
         * GET /admin/carousels/scheduled - List upcoming scheduled carousels
         */
        @GetMapping("/scheduled")
        public ResponseEntity<Map<String, Object>> getScheduledCarousels() {
                log.info("GET /admin/carousels/scheduled");

                try {
                        List<AdminCarousel> carousels = carouselService.getScheduledCarousels();

                        return ResponseEntity.ok(Map.of(
                                        "success", true,
                                        "message", "Scheduled carousels retrieved successfully",
                                        "data", carousels,
                                        "count", carousels.size()));
                } catch (Exception e) {
                        log.error("Error retrieving scheduled carousels", e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(Map.of(
                                                        "success", false,
                                                        "message",
                                                        "Failed to retrieve scheduled carousels: " + e.getMessage()));
                }
        }

        /**
         * GET /admin/carousels/:id - Get details of a carousel
         */
        @GetMapping("/{id}")
        public ResponseEntity<Map<String, Object>> getCarouselById(@PathVariable String id) {
                log.info("GET /admin/carousels/{}", id);

                try {
                        Optional<AdminCarousel> carousel = carouselService.getCarouselById(id);

                        if (carousel.isPresent()) {
                                return ResponseEntity.ok(Map.of(
                                                "success", true,
                                                "message", "Carousel retrieved successfully",
                                                "data", carousel.get()));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(Map.of(
                                                                "success", false,
                                                                "message", "Carousel not found with ID: " + id));
                        }
                } catch (Exception e) {
                        log.error("Error retrieving carousel: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(Map.of(
                                                        "success", false,
                                                        "message", "Failed to retrieve carousel: " + e.getMessage()));
                }
        }

        /**
         * POST /admin/carousels - Create a new carousel
         */
        @PostMapping
        public ResponseEntity<Map<String, Object>> createCarousel(@RequestBody AdminCarousel carousel) {
                log.info("POST /admin/carousels - Creating carousel: {}", carousel.getTitle());

                try {
                        AdminCarousel createdCarousel = carouselService.createCarousel(carousel);

                        return ResponseEntity.status(HttpStatus.CREATED)
                                        .body(Map.of(
                                                        "success", true,
                                                        "message", "Carousel created successfully",
                                                        "data", createdCarousel));
                } catch (Exception e) {
                        log.error("Error creating carousel", e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(Map.of(
                                                        "success", false,
                                                        "message", "Failed to create carousel: " + e.getMessage()));
                }
        }

        /**
         * PUT /admin/carousels/:id - Update carousel details
         */
        @PutMapping("/{id}")
        public ResponseEntity<Map<String, Object>> updateCarousel(
                        @PathVariable String id,
                        @RequestBody AdminCarousel carousel) {

                log.info("PUT /admin/carousels/{} - Updating carousel", id);

                try {
                        Optional<AdminCarousel> updatedCarousel = carouselService.updateCarousel(id, carousel);

                        if (updatedCarousel.isPresent()) {
                                return ResponseEntity.ok(Map.of(
                                                "success", true,
                                                "message", "Carousel updated successfully",
                                                "data", updatedCarousel.get()));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(Map.of(
                                                                "success", false,
                                                                "message", "Carousel not found with ID: " + id));
                        }
                } catch (Exception e) {
                        log.error("Error updating carousel: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(Map.of(
                                                        "success", false,
                                                        "message", "Failed to update carousel: " + e.getMessage()));
                }
        }

        /**
         * DELETE /admin/carousels/:id - Soft delete a carousel
         */
        @DeleteMapping("/{id}")
        public ResponseEntity<Map<String, Object>> deleteCarousel(
                        @PathVariable String id,
                        @RequestParam(defaultValue = "system") String deletedBy) {

                log.info("DELETE /admin/carousels/{} - Soft deleting carousel", id);

                try {
                        boolean deleted = carouselService.softDeleteCarousel(id, deletedBy);

                        if (deleted) {
                                return ResponseEntity.ok(Map.of(
                                                "success", true,
                                                "message", "Carousel deleted successfully"));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(Map.of(
                                                                "success", false,
                                                                "message", "Carousel not found with ID: " + id));
                        }
                } catch (Exception e) {
                        log.error("Error deleting carousel: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(Map.of(
                                                        "success", false,
                                                        "message", "Failed to delete carousel: " + e.getMessage()));
                }
        }

        /**
         * PUT /admin/carousels/:id/restore - Restore a deleted carousel
         */
        @PutMapping("/{id}/restore")
        public ResponseEntity<Map<String, Object>> restoreCarousel(
                        @PathVariable String id,
                        @RequestParam(defaultValue = "system") String restoredBy) {

                log.info("PUT /admin/carousels/{}/restore - Restoring carousel", id);

                try {
                        boolean restored = carouselService.restoreCarousel(id, restoredBy);

                        if (restored) {
                                return ResponseEntity.ok(Map.of(
                                                "success", true,
                                                "message", "Carousel restored successfully"));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(Map.of(
                                                                "success", false,
                                                                "message", "Carousel not found with ID: " + id));
                        }
                } catch (Exception e) {
                        log.error("Error restoring carousel: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(Map.of(
                                                        "success", false,
                                                        "message", "Failed to restore carousel: " + e.getMessage()));
                }
        }

        /**
         * PUT /admin/carousels/:id/status - Change status (active/inactive/draft)
         */
        @PutMapping("/{id}/status")
        public ResponseEntity<Map<String, Object>> updateCarouselStatus(
                        @PathVariable String id,
                        @RequestParam String status,
                        @RequestParam(defaultValue = "system") String updatedBy) {

                log.info("PUT /admin/carousels/{}/status - Updating status to: {}", id, status);

                try {
                        // Validate status
                        if (!List.of("active", "inactive", "draft").contains(status)) {
                                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                                .body(Map.of(
                                                                "success", false,
                                                                "message",
                                                                "Invalid status. Must be one of: active, inactive, draft"));
                        }

                        boolean updated = carouselService.updateCarouselStatus(id, status, updatedBy);

                        if (updated) {
                                return ResponseEntity.ok(Map.of(
                                                "success", true,
                                                "message", "Carousel status updated successfully",
                                                "status", status));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(Map.of(
                                                                "success", false,
                                                                "message", "Carousel not found with ID: " + id));
                        }
                } catch (Exception e) {
                        log.error("Error updating carousel status: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(Map.of(
                                                        "success", false,
                                                        "message",
                                                        "Failed to update carousel status: " + e.getMessage()));
                }
        }

        /**
         * Health check endpoint
         */
        @GetMapping("/health")
        public ResponseEntity<Map<String, Object>> healthCheck() {
                return ResponseEntity.ok(Map.of(
                                "success", true,
                                "message", "Carousel service is running",
                                "service", "carousel",
                                "timestamp", System.currentTimeMillis()));
        }
}