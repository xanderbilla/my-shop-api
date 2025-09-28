package com.shop.carousel.controller;

import com.shop.carousel.dto.ApiResponse;
import com.shop.carousel.model.AdminCarousel;
import com.shop.carousel.service.CarouselService;
import com.shop.carousel.service.AdminSecurityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

/**
 * Admin Carousel Controller for Carousel Service
 * 
 * 🔒 SECURITY: ALL ENDPOINTS REQUIRE ADMIN AUTHENTICATION via @PreAuthorize
 * 
 * Features:
 * ✅ JWT-based authentication with Cognito
 * ✅ ADMIN group verification for access control
 * ✅ Method-level security with @PreAuthorize annotations
 * ✅ Secure carousel data access from DynamoDB
 * ✅ Complete CRUD operations for carousel management
 * ✅ Audit logging with admin user tracking
 * 
 * Security Flow:
 * 1. @PreAuthorize("@adminSecurityService.isAdmin()") - Declarative security
 * 2. JWT token extraction from access_token cookie
 * 3. Token signature verification using Cognito JWKS
 * 4. Token expiry and issuer validation
 * 5. ADMIN group membership verification
 * 
 * @author Vikas Singh
 * @version 2.0 (Added Authentication)
 * @since 2025-09-27
 */
@RestController
@RequestMapping("/admin/carousels")
@RequiredArgsConstructor
@Slf4j
public class CarouselController {

        private final CarouselService carouselService;
        private final AdminSecurityService adminSecurityService;

        /**
         * GET /admin/carousels - List all carousels
         * GET /admin/carousels?type=homepage - Filter by placement type
         * GET /admin/carousels?status=active - Filter by status
         * 
         * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
         */
        @GetMapping
        @PreAuthorize("@adminSecurityService.isAdmin()")
        public ResponseEntity<ApiResponse<List<AdminCarousel>>> getAllCarousels(
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

                        return ResponseEntity.ok(
                                        ApiResponse.success("Carousels retrieved successfully", carousels));
                } catch (Exception e) {
                        log.error("Error retrieving carousels", e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to retrieve carousels: " + e.getMessage(),
                                                        500));
                }
        }

        /**
         * GET /admin/carousels/scheduled - List upcoming scheduled carousels
         * 
         * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
         */
        @GetMapping("/scheduled")
        @PreAuthorize("@adminSecurityService.isAdmin()")
        public ResponseEntity<ApiResponse<List<AdminCarousel>>> getScheduledCarousels() {
                log.info("GET /admin/carousels/scheduled");

                try {
                        List<AdminCarousel> carousels = carouselService.getScheduledCarousels();

                        return ResponseEntity.ok(
                                        ApiResponse.success("Scheduled carousels retrieved successfully", carousels));
                } catch (Exception e) {
                        log.error("Error retrieving scheduled carousels", e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error(
                                                        "Failed to retrieve scheduled carousels: " + e.getMessage(),
                                                        500));
                }
        }

        /**
         * GET /admin/carousels/:id - Get details of a carousel
         * 
         * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
         */
        @GetMapping("/{id}")
        @PreAuthorize("@adminSecurityService.isAdmin()")
        public ResponseEntity<ApiResponse<AdminCarousel>> getCarouselById(@PathVariable String id) {
                log.info("GET /admin/carousels/{}", id);

                try {
                        Optional<AdminCarousel> carousel = carouselService.getCarouselById(id);

                        if (carousel.isPresent()) {
                                return ResponseEntity.ok(
                                                ApiResponse.success("Carousel retrieved successfully", carousel.get()));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(ApiResponse.error("Carousel not found with ID: " + id, 404));
                        }
                } catch (Exception e) {
                        log.error("Error retrieving carousel: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to retrieve carousel: " + e.getMessage(), 500));
                }
        }

        /**
         * POST /admin/carousels - Create a new carousel
         * 
         * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
         */
        @PostMapping
        @PreAuthorize("@adminSecurityService.isAdmin()")
        public ResponseEntity<ApiResponse<AdminCarousel>> createCarousel(@RequestBody AdminCarousel carousel) {
                log.info("POST /admin/carousels - Creating carousel: {}", carousel.getTitle());

                try {
                        AdminCarousel createdCarousel = carouselService.createCarousel(carousel);

                        return ResponseEntity.status(HttpStatus.CREATED)
                                        .body(ApiResponse.success("Carousel created successfully", createdCarousel));
                } catch (Exception e) {
                        log.error("Error creating carousel", e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to create carousel: " + e.getMessage(), 500));
                }
        }

        /**
         * PUT /admin/carousels/:id - Update carousel details
         * 
         * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
         */
        @PutMapping("/{id}")
        @PreAuthorize("@adminSecurityService.isAdmin()")
        public ResponseEntity<ApiResponse<AdminCarousel>> updateCarousel(
                        @PathVariable String id,
                        @RequestBody AdminCarousel carousel) {

                log.info("PUT /admin/carousels/{} - Updating carousel", id);

                try {
                        Optional<AdminCarousel> updatedCarousel = carouselService.updateCarousel(id, carousel);

                        if (updatedCarousel.isPresent()) {
                                return ResponseEntity.ok(
                                                ApiResponse.success("Carousel updated successfully",
                                                                updatedCarousel.get()));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(ApiResponse.error("Carousel not found with ID: " + id, 404));
                        }
                } catch (Exception e) {
                        log.error("Error updating carousel: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to update carousel: " + e.getMessage(), 500));
                }
        }

        /**
         * DELETE /admin/carousels/:id - Soft delete a carousel
         * 
         * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
         */
        @DeleteMapping("/{id}")
        @PreAuthorize("@adminSecurityService.isAdmin()")
        public ResponseEntity<ApiResponse<String>> deleteCarousel(
                        @PathVariable String id,
                        @RequestParam(defaultValue = "system") String deletedBy) {

                log.info("DELETE /admin/carousels/{} - Soft deleting carousel", id);

                try {
                        boolean deleted = carouselService.softDeleteCarousel(id, deletedBy);

                        if (deleted) {
                                return ResponseEntity.ok(
                                                ApiResponse.success("Carousel deleted successfully"));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(ApiResponse.error("Carousel not found with ID: " + id, 404));
                        }
                } catch (Exception e) {
                        log.error("Error deleting carousel: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to delete carousel: " + e.getMessage(), 500));
                }
        }

        /**
         * PUT /admin/carousels/:id/restore - Restore a deleted carousel
         * 
         * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
         */
        @PutMapping("/{id}/restore")
        @PreAuthorize("@adminSecurityService.isAdmin()")
        public ResponseEntity<ApiResponse<String>> restoreCarousel(
                        @PathVariable String id,
                        @RequestParam(defaultValue = "system") String restoredBy) {

                log.info("PUT /admin/carousels/{}/restore - Restoring carousel", id);

                try {
                        boolean restored = carouselService.restoreCarousel(id, restoredBy);

                        if (restored) {
                                return ResponseEntity.ok(
                                                ApiResponse.success("Carousel restored successfully"));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(ApiResponse.error("Carousel not found with ID: " + id, 404));
                        }
                } catch (Exception e) {
                        log.error("Error restoring carousel: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to restore carousel: " + e.getMessage(), 500));
                }
        }

        /**
         * PUT /admin/carousels/:id/status - Change status (active/inactive/draft)
         * 
         * 🔒 SECURITY: Requires valid JWT token with ADMIN group membership
         */
        @PutMapping("/{id}/status")
        @PreAuthorize("@adminSecurityService.isAdmin()")
        public ResponseEntity<ApiResponse<String>> updateCarouselStatus(
                        @PathVariable String id,
                        @RequestParam String status,
                        @RequestParam(defaultValue = "system") String updatedBy) {

                log.info("PUT /admin/carousels/{}/status - Updating status to: {}", id, status);

                try {
                        // Validate status
                        if (!List.of("active", "inactive", "draft").contains(status)) {
                                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                                .body(ApiResponse.error(
                                                                "Invalid status. Must be one of: active, inactive, draft",
                                                                400));
                        }

                        boolean updated = carouselService.updateCarouselStatus(id, status, updatedBy);

                        if (updated) {
                                return ResponseEntity.ok(
                                                ApiResponse.success(
                                                                "Carousel status updated successfully to: " + status));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(ApiResponse.error("Carousel not found with ID: " + id, 404));
                        }
                } catch (Exception e) {
                        log.error("Error updating carousel status: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to update carousel status: " + e.getMessage(),
                                                        500));
                }
        }

}