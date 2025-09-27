package com.shop.categories.controller;

import com.shop.categories.dto.ApiResponse;
import com.shop.categories.dto.CategoryRequestDto;
import com.shop.categories.model.AdminCategory;
import com.shop.categories.model.DeleteStatus;
import com.shop.categories.service.CategoryService;
import com.shop.categories.util.SlugUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/admin/categories")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "*") // Allow cross-origin for easy testing
public class CategoryController {

        private final CategoryService categoryService;

        /**
         * GET /admin/categories - List all categories
         * GET /admin/categories?isActive=true - Filter by active status
         * GET /admin/categories?includeDeleted=true - Include deleted categories
         */
        @GetMapping
        public ResponseEntity<ApiResponse<List<AdminCategory>>> getAllCategories(
                        @RequestParam(required = false) Boolean isActive,
                        @RequestParam(defaultValue = "false") Boolean includeDeleted) {

                log.info("GET /admin/categories - isActive: {}, includeDeleted: {}", isActive, includeDeleted);

                try {
                        List<AdminCategory> categories = categoryService.getAllCategories(isActive, includeDeleted);

                        return ResponseEntity.ok(
                                        ApiResponse.success("Categories retrieved successfully", categories));
                } catch (Exception e) {
                        log.error("Error fetching categories", e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to fetch categories: " + e.getMessage(), 500));
                }
        }

        /**
         * GET /admin/categories/top-level - Get top-level categories (no parent)
         */
        @GetMapping("/top-level")
        public ResponseEntity<ApiResponse<List<AdminCategory>>> getTopLevelCategories(
                        @RequestParam(required = false) Boolean isActive) {

                log.info("GET /admin/categories/top-level - isActive: {}", isActive);

                try {
                        List<AdminCategory> categories = categoryService.getTopLevelCategories(isActive);

                        return ResponseEntity.ok(
                                        ApiResponse.success("Top-level categories retrieved successfully", categories));
                } catch (Exception e) {
                        log.error("Error fetching top-level categories", e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error(
                                                        "Failed to fetch top-level categories: " + e.getMessage(),
                                                        500));
                }
        }

        /**
         * GET /admin/categories/:id - Get details of one category
         */
        @GetMapping("/{id}")
        public ResponseEntity<ApiResponse<AdminCategory>> getCategoryById(@PathVariable String id) {
                log.info("GET /admin/categories/{}", id);

                try {
                        Optional<AdminCategory> category = categoryService.getCategoryById(id);

                        if (category.isPresent()) {
                                return ResponseEntity.ok(
                                                ApiResponse.success("Category retrieved successfully", category.get()));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(ApiResponse.error("Category not found with ID: " + id, 404));
                        }
                } catch (Exception e) {
                        log.error("Error fetching category: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to fetch category: " + e.getMessage(), 500));
                }
        }

        /**
         * GET /admin/categories/:id/subcategories - Get child categories
         */
        @GetMapping("/{id}/subcategories")
        public ResponseEntity<ApiResponse<List<AdminCategory>>> getSubcategories(
                        @PathVariable String id,
                        @RequestParam(required = false) Boolean isActive) {

                log.info("GET /admin/categories/{}/subcategories - isActive: {}", id, isActive);

                try {
                        List<AdminCategory> subcategories = categoryService.getSubcategories(id, isActive);

                        return ResponseEntity.ok(
                                        ApiResponse.success("Subcategories retrieved successfully", subcategories));
                } catch (Exception e) {
                        log.error("Error fetching subcategories for: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to fetch subcategories: " + e.getMessage(),
                                                        500));
                }
        }

        /**
         * POST /admin/categories - Create a new category
         */
        @PostMapping
        public ResponseEntity<ApiResponse<AdminCategory>> createCategory(
                        @Valid @RequestBody CategoryRequestDto categoryRequest,
                        BindingResult bindingResult) {

                log.info("POST /admin/categories - Creating category: {}", categoryRequest.getName());

                // Check for validation errors
                if (bindingResult.hasErrors()) {
                        String errors = bindingResult.getFieldErrors().stream()
                                        .map(error -> error.getField() + ": " + error.getDefaultMessage())
                                        .collect(Collectors.joining(", "));

                        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                        .body(ApiResponse.error("Validation failed: " + errors, 400));
                }

                try {
                        // Convert DTO to entity
                        AdminCategory category = AdminCategory.builder()
                                        .id(UUID.randomUUID().toString())
                                        .name(categoryRequest.getName())
                                        .description(categoryRequest.getDescription())
                                        .categoryName(SlugUtils.generateSlug(categoryRequest.getName())) // Auto-generate
                                                                                                         // slug
                                        .priority(categoryRequest.getPriority())
                                        .isActive(categoryRequest.getIsActive())
                                        .image(categoryRequest.getImage())
                                        .parentId(null) // Top-level category
                                        .createdAt(LocalDateTime.now())
                                        .updatedAt(null) // null when creating
                                        .deleteStatus(DeleteStatus.builder().build()) // Initialize with default status
                                        .build();

                        AdminCategory createdCategory = categoryService.createCategory(category);

                        return ResponseEntity.status(HttpStatus.CREATED)
                                        .body(ApiResponse.success("Category created successfully", createdCategory));
                } catch (Exception e) {
                        log.error("Error creating category", e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to create category: " + e.getMessage(), 500));
                }
        }

        /**
         * POST /admin/categories/:id/subcategories - Create child category
         */
        @PostMapping("/{id}/subcategories")
        public ResponseEntity<ApiResponse<AdminCategory>> createSubcategory(
                        @PathVariable String id,
                        @Valid @RequestBody CategoryRequestDto subcategoryRequest,
                        BindingResult bindingResult) {

                log.info("POST /admin/categories/{}/subcategories - Creating subcategory: {}", id,
                                subcategoryRequest.getName());

                // Check for validation errors
                if (bindingResult.hasErrors()) {
                        String errors = bindingResult.getFieldErrors().stream()
                                        .map(error -> error.getField() + ": " + error.getDefaultMessage())
                                        .collect(Collectors.joining(", "));

                        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                        .body(ApiResponse.error("Validation failed: " + errors, 400));
                }

                try {
                        // Verify parent category exists
                        Optional<AdminCategory> parentCategory = categoryService.getCategoryById(id);
                        if (!parentCategory.isPresent()) {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(ApiResponse.error("Parent category not found with ID: " + id,
                                                                404));
                        }

                        // Convert DTO to entity with parent ID
                        AdminCategory subcategory = AdminCategory.builder()
                                        .id(UUID.randomUUID().toString())
                                        .name(subcategoryRequest.getName())
                                        .description(subcategoryRequest.getDescription())
                                        .categoryName(SlugUtils.generateSlug(subcategoryRequest.getName())) // Auto-generate
                                                                                                            // slug
                                        .priority(subcategoryRequest.getPriority())
                                        .isActive(subcategoryRequest.getIsActive())
                                        .image(subcategoryRequest.getImage())
                                        .parentId(id) // Set parent ID
                                        .createdAt(LocalDateTime.now())
                                        .updatedAt(null) // null when creating
                                        .deleteStatus(DeleteStatus.builder().build()) // Initialize with default status
                                        .build();

                        AdminCategory createdSubcategory = categoryService.createCategory(subcategory);

                        return ResponseEntity.status(HttpStatus.CREATED)
                                        .body(ApiResponse.success("Subcategory created successfully",
                                                        createdSubcategory));
                } catch (Exception e) {
                        log.error("Error creating subcategory for parent: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to create subcategory: " + e.getMessage(),
                                                        500));
                }
        }

        /**
         * PUT /admin/categories/:id - Update category details
         */
        @PutMapping("/{id}")
        public ResponseEntity<ApiResponse<AdminCategory>> updateCategory(
                        @PathVariable String id,
                        @Valid @RequestBody CategoryRequestDto categoryRequest,
                        BindingResult bindingResult) {

                log.info("PUT /admin/categories/{} - Updating category", id);

                // Check for validation errors
                if (bindingResult.hasErrors()) {
                        String errors = bindingResult.getFieldErrors().stream()
                                        .map(error -> error.getField() + ": " + error.getDefaultMessage())
                                        .collect(Collectors.joining(", "));

                        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                        .body(ApiResponse.error("Validation failed: " + errors, 400));
                }

                try {
                        // Get existing category to preserve certain fields
                        Optional<AdminCategory> existingCategory = categoryService.getCategoryById(id);
                        if (!existingCategory.isPresent()) {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(ApiResponse.error("Category not found with ID: " + id, 404));
                        }

                        // Build updated category preserving created fields
                        AdminCategory categoryToUpdate = AdminCategory.builder()
                                        .id(id)
                                        .name(categoryRequest.getName())
                                        .description(categoryRequest.getDescription())
                                        .categoryName(SlugUtils.generateSlug(categoryRequest.getName())) // Regenerate
                                                                                                         // slug
                                        .priority(categoryRequest.getPriority())
                                        .isActive(categoryRequest.getIsActive())
                                        .image(categoryRequest.getImage())
                                        .parentId(existingCategory.get().getParentId()) // Preserve parent relationship
                                        .createdAt(existingCategory.get().getCreatedAt()) // Preserve creation time
                                        .createdBy(existingCategory.get().getCreatedBy()) // Preserve creator
                                        .updatedAt(LocalDateTime.now()) // Update timestamp
                                        .deleteStatus(existingCategory.get().getDeleteStatus()) // Preserve deletion
                                                                                                // status
                                        .build();

                        Optional<AdminCategory> updatedCategory = categoryService.updateCategory(id, categoryToUpdate);

                        if (updatedCategory.isPresent()) {
                                return ResponseEntity.ok(
                                                ApiResponse.success("Category updated successfully",
                                                                updatedCategory.get()));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(ApiResponse.error("Category not found with ID: " + id, 404));
                        }
                } catch (Exception e) {
                        log.error("Error updating category: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to update category: " + e.getMessage(), 500));
                }
        }

        /**
         * DELETE /admin/categories/:id - Soft delete category
         */
        @DeleteMapping("/{id}")
        public ResponseEntity<ApiResponse<String>> deleteCategory(
                        @PathVariable String id,
                        @RequestParam(defaultValue = "system") String deletedBy) {

                log.info("DELETE /admin/categories/{} - Soft deleting category", id);

                try {
                        boolean deleted = categoryService.softDeleteCategory(id, deletedBy);

                        if (deleted) {
                                return ResponseEntity.ok(
                                                ApiResponse.success("Category deleted successfully"));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(ApiResponse.error(
                                                                "Category not found or already deleted with ID: " + id,
                                                                404));
                        }
                } catch (Exception e) {
                        log.error("Error deleting category: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to delete category: " + e.getMessage(), 500));
                }
        }

        /**
         * PUT /admin/categories/:id/restore - Restore a deleted category
         */
        @PutMapping("/{id}/restore")
        public ResponseEntity<ApiResponse<String>> restoreCategory(
                        @PathVariable String id,
                        @RequestParam(defaultValue = "system") String restoredBy) {

                log.info("PUT /admin/categories/{}/restore - Restoring category", id);

                try {
                        boolean restored = categoryService.restoreCategory(id, restoredBy);

                        if (restored) {
                                return ResponseEntity.ok(
                                                ApiResponse.success("Category restored successfully"));
                        } else {
                                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                .body(ApiResponse.error("Category not found with ID: " + id, 404));
                        }
                } catch (Exception e) {
                        log.error("Error restoring category: {}", id, e);
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                        .body(ApiResponse.error("Failed to restore category: " + e.getMessage(), 500));
                }
        }
}