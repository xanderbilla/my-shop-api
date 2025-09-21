package com.shop.categories.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@DynamoDbBean
public class DeleteStatus {

    @Builder.Default
    private Boolean isDeleted = false;

    @Builder.Default
    private Integer restoresCount = 0;

    private LocalDateTime deletedAt;

    private LocalDateTime restoredAt;

    private String deletedBy;

    private String restoredBy;

    /**
     * Mark as deleted
     */
    public void markDeleted(String deletedBy) {
        this.isDeleted = true;
        this.deletedAt = LocalDateTime.now();
        this.deletedBy = deletedBy;
        // Don't reset restored fields when deleting again
    }

    /**
     * Mark as restored
     */
    public void markRestored(String restoredBy) {
        this.isDeleted = false;
        this.restoredAt = LocalDateTime.now();
        this.restoredBy = restoredBy;
        this.restoresCount = (this.restoresCount != null ? this.restoresCount : 0) + 1;
    }
}