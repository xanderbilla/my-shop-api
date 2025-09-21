package com.shop.carousel.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@DynamoDbBean
public class AdminCarousel {

    private String id;
    private String title;
    private CarouselImages images;
    private String ctaText;
    private String ctaLink;
    private Integer priority;
    private LocalDateTime startDate;
    private LocalDateTime endDate;
    private String status; // "active", "inactive", "draft"
    private String type; // "homepage", "category", "custom"
    private CarouselMetadata metadata;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String createdBy;
    private String updatedBy;
    private DeleteStatus deleteStatus;

    @DynamoDbPartitionKey
    public String getId() {
        return id;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class CarouselImages {
        private ImageData desktop;
        private ImageData tablet;
        private ImageData mobile;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class ImageData {
        private String src;
        private String alt;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class CarouselMetadata {
        private String backgroundColor;
        private String textColor;
        private String target; // "_self" or "_blank"
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class DeleteStatus {
        private Boolean isDeleted;
        private Integer restoresCount;
        private LocalDateTime deletedAt;
        private LocalDateTime restoreAt;
        private String deletedBy;
        private String restoredBy;
    }
}