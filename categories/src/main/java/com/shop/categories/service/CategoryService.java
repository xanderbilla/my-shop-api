package com.shop.categories.service;

import com.shop.categories.model.AdminCategory;
import com.shop.categories.model.DeleteStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.*;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class CategoryService {

    private final DynamoDbTable<AdminCategory> categoriesTable;

    /**
     * Get all categories with optional filtering
     */
    public List<AdminCategory> getAllCategories(Boolean isActive, Boolean includeDeleted) {
        log.info("Fetching all categories - isActive: {}, includeDeleted: {}", isActive, includeDeleted);

        ScanEnhancedRequest.Builder requestBuilder = ScanEnhancedRequest.builder();

        // Build filter expression
        String filterExpression = "";
        if (!includeDeleted) {
            filterExpression = "attribute_not_exists(deleteStatus.isDeleted) OR deleteStatus.isDeleted = :notDeleted";
        }
        if (isActive != null) {
            if (!filterExpression.isEmpty()) {
                filterExpression += " AND ";
            }
            filterExpression += "isActive = :isActive";
        }

        if (!filterExpression.isEmpty()) {
            Expression.Builder expressionBuilder = Expression.builder().expression(filterExpression);
            if (!includeDeleted) {
                expressionBuilder.putExpressionValue(":notDeleted", AttributeValue.builder().bool(false).build());
            }
            if (isActive != null) {
                expressionBuilder.putExpressionValue(":isActive", AttributeValue.builder().bool(isActive).build());
            }
            requestBuilder.filterExpression(expressionBuilder.build());
        }

        return categoriesTable.scan(requestBuilder.build())
                .stream()
                .flatMap(page -> page.items().stream())
                .collect(Collectors.toList());
    }

    /**
     * Get category by ID
     */
    public Optional<AdminCategory> getCategoryById(String id) {
        log.info("Fetching category by ID: {}", id);
        AdminCategory category = categoriesTable.getItem(Key.builder().partitionValue(id).build());
        return Optional.ofNullable(category);
    }

    /**
     * Get category by slug (categoryName)
     */
    public Optional<AdminCategory> getCategoryBySlug(String categoryName) {
        log.info("Fetching category by slug: {}", categoryName);

        QueryEnhancedRequest request = QueryEnhancedRequest.builder()
                .queryConditional(QueryConditional.keyEqualTo(Key.builder().partitionValue(categoryName).build()))
                .build();

        List<AdminCategory> categories = categoriesTable.index("categoryName-index")
                .query(request)
                .stream()
                .flatMap(page -> page.items().stream())
                .collect(Collectors.toList());

        return categories.isEmpty() ? Optional.empty() : Optional.of(categories.get(0));
    }

    /**
     * Get subcategories (children) of a parent category
     */
    public List<AdminCategory> getSubcategories(String parentId, Boolean isActive) {
        log.info("Fetching subcategories for parent: {}, isActive: {}", parentId, isActive);

        QueryEnhancedRequest.Builder requestBuilder = QueryEnhancedRequest.builder()
                .queryConditional(QueryConditional.keyEqualTo(Key.builder().partitionValue(parentId).build()));

        // Add filter for active status if specified
        if (isActive != null) {
            Expression filterExpression = Expression.builder()
                    .expression(
                            "isActive = :isActive AND (attribute_not_exists(deleteStatus.isDeleted) OR deleteStatus.isDeleted = :notDeleted)")
                    .putExpressionValue(":isActive", AttributeValue.builder().bool(isActive).build())
                    .putExpressionValue(":notDeleted", AttributeValue.builder().bool(false).build())
                    .build();
            requestBuilder.filterExpression(filterExpression);
        }

        return categoriesTable.index("parentId-index")
                .query(requestBuilder.build())
                .stream()
                .flatMap(page -> page.items().stream())
                .collect(Collectors.toList());
    }

    /**
     * Create a new category
     */
    public AdminCategory createCategory(AdminCategory category) {
        log.info("Creating new category: {}", category.getName());

        // Set default values
        category.setId(UUID.randomUUID().toString());
        category.setCreatedAt(LocalDateTime.now());
        // Don't set updatedAt when creating - keep it null

        // Set defaults if not provided
        if (category.getIsActive() == null) {
            category.setIsActive(true);
        }
        if (category.getDeleteStatus() == null) {
            category.setDeleteStatus(DeleteStatus.builder().build());
        }
        if (category.getPriority() == null) {
            category.setPriority(0);
        }

        categoriesTable.putItem(category);
        log.info("Created category: {}", category.getId());
        return category;
    }

    /**
     * Update an existing category
     */
    public Optional<AdminCategory> updateCategory(String id, AdminCategory updatedCategory) {
        log.info("Updating category: {}", id);

        Optional<AdminCategory> existingCategory = getCategoryById(id);
        if (existingCategory.isPresent()) {
            AdminCategory category = existingCategory.get();

            // Update fields
            if (updatedCategory.getName() != null) {
                category.setName(updatedCategory.getName());
            }
            if (updatedCategory.getCategoryName() != null) {
                category.setCategoryName(updatedCategory.getCategoryName());
            }
            if (updatedCategory.getDescription() != null) {
                category.setDescription(updatedCategory.getDescription());
            }
            if (updatedCategory.getImage() != null) {
                category.setImage(updatedCategory.getImage());
            }
            if (updatedCategory.getPriority() != null) {
                category.setPriority(updatedCategory.getPriority());
            }
            if (updatedCategory.getIsActive() != null) {
                category.setIsActive(updatedCategory.getIsActive());
            }
            if (updatedCategory.getParentId() != null) {
                category.setParentId(updatedCategory.getParentId());
            }
            if (updatedCategory.getUpdatedBy() != null) {
                category.setUpdatedBy(updatedCategory.getUpdatedBy());
            }

            category.setUpdatedAt(LocalDateTime.now());

            categoriesTable.putItem(category);
            log.info("Updated category: {}", id);
            return Optional.of(category);
        }

        log.warn("Category not found for update: {}", id);
        return Optional.empty();
    }

    /**
     * Soft delete a category
     */
    public boolean softDeleteCategory(String id, String deletedBy) {
        log.info("Soft deleting category: {}", id);

        Optional<AdminCategory> existingCategory = getCategoryById(id);
        if (existingCategory.isPresent()) {
            AdminCategory category = existingCategory.get();

            // Check if already deleted
            if (category.getIsDeleted()) {
                log.warn("Category is already deleted: {}", id);
                return false;
            }

            category.markAsDeleted(deletedBy);
            categoriesTable.putItem(category);
            log.info("Soft deleted category: {}", id);
            return true;
        }

        log.warn("Category not found for deletion: {}", id);
        return false;
    }

    /**
     * Restore a deleted category
     */
    public boolean restoreCategory(String id, String restoredBy) {
        log.info("Restoring category: {}", id);

        Optional<AdminCategory> existingCategory = getCategoryById(id);
        if (existingCategory.isPresent()) {
            AdminCategory category = existingCategory.get();

            category.markAsRestored(restoredBy);
            categoriesTable.putItem(category);
            log.info("Restored category: {}", id);
            return true;
        }

        log.warn("Category not found for restoration: {}", id);
        return false;
    }

    /**
     * Get top-level categories (no parent)
     */
    public List<AdminCategory> getTopLevelCategories(Boolean isActive) {
        log.info("Fetching top-level categories - isActive: {}", isActive);

        ScanEnhancedRequest.Builder requestBuilder = ScanEnhancedRequest.builder();

        String filterExpression = "attribute_not_exists(parentId) AND (attribute_not_exists(deleteStatus.isDeleted) OR deleteStatus.isDeleted = :notDeleted)";
        Expression.Builder expressionBuilder = Expression.builder()
                .expression(filterExpression)
                .putExpressionValue(":notDeleted", AttributeValue.builder().bool(false).build());

        if (isActive != null) {
            filterExpression += " AND isActive = :isActive";
            expressionBuilder.putExpressionValue(":isActive", AttributeValue.builder().bool(isActive).build());
        }

        requestBuilder.filterExpression(expressionBuilder.expression(filterExpression).build());

        return categoriesTable.scan(requestBuilder.build())
                .stream()
                .flatMap(page -> page.items().stream())
                .collect(Collectors.toList());
    }
}