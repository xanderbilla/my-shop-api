package com.shop.categories.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@DynamoDbBean
public class AdminCategory {

    private String id; // UUID
    private String name; // display name e.g., "Women's Fashion"
    private String categoryName; // slug e.g., "womens-fashion"
    private String description; // optional description
    private String image; // category banner/icon (nullable)
    private Integer priority; // for ordering
    private Boolean isActive; // enable/disable visibility
    private String parentId; // parent category (null = top-level)
    private LocalDateTime createdAt; // timestamp
    private LocalDateTime updatedAt; // timestamp
    private String createdBy; // admin who created this category
    private String updatedBy; // admin who last updated
    private DeleteStatus deleteStatus; // comprehensive deletion tracking

    @DynamoDbPartitionKey
    public String getId() {
        return this.id;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = { "parentId-index" })
    public String getParentId() {
        return this.parentId;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = { "categoryName-index" })
    public String getCategoryName() {
        return this.categoryName;
    }

    public Boolean getIsActive() {
        return this.isActive;
    }

    public DeleteStatus getDeleteStatus() {
        return this.deleteStatus;
    }

    // Convenience method for backward compatibility and easy checking
    public Boolean getIsDeleted() {
        return this.deleteStatus != null ? Boolean.TRUE.equals(this.deleteStatus.getIsDeleted()) : false;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setCategoryName(String categoryName) {
        this.categoryName = categoryName;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void setImage(String image) {
        this.image = image;
    }

    public void setPriority(Integer priority) {
        this.priority = priority;
    }

    public void setIsActive(Boolean isActive) {
        this.isActive = isActive;
    }

    public void setParentId(String parentId) {
        this.parentId = parentId;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }

    public void setDeleteStatus(DeleteStatus deleteStatus) {
        this.deleteStatus = deleteStatus;
    }

    // Convenience method for backward compatibility
    public void setIsDeleted(Boolean isDeleted) {
        if (this.deleteStatus == null) {
            this.deleteStatus = DeleteStatus.builder().build();
        }
        this.deleteStatus.setIsDeleted(isDeleted);
    }

    // Helper methods for deletion operations
    public void markAsDeleted(String deletedBy) {
        if (this.deleteStatus == null) {
            this.deleteStatus = DeleteStatus.builder().build();
        }
        this.deleteStatus.markDeleted(deletedBy);
        this.setUpdatedAt(LocalDateTime.now());
        this.setUpdatedBy(deletedBy);
    }

    public void markAsRestored(String restoredBy) {
        if (this.deleteStatus == null) {
            this.deleteStatus = DeleteStatus.builder().build();
        }
        this.deleteStatus.markRestored(restoredBy);
        this.setUpdatedAt(LocalDateTime.now());
        this.setUpdatedBy(restoredBy);
    }
}