package com.shop.carousel.service;

import com.shop.carousel.model.AdminCarousel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class CarouselService {

    private final DynamoDbTable<AdminCarousel> carouselTable;

    public List<AdminCarousel> getAllCarousels() {
        log.info("Fetching all carousels");
        return carouselTable.scan().items().stream().collect(Collectors.toList());
    }

    public List<AdminCarousel> getCarouselsByType(String type) {
        log.info("Fetching carousels by type: {}", type);
        ScanEnhancedRequest request = ScanEnhancedRequest.builder()
                .filterExpression(Expression.builder()
                        .expression("#type = :type")
                        .putExpressionName("#type", "type")
                        .putExpressionValue(":type", AttributeValue.builder().s(type).build())
                        .build())
                .build();

        return carouselTable.scan(request).items().stream().collect(Collectors.toList());
    }

    public List<AdminCarousel> getCarouselsByStatus(String status) {
        log.info("Fetching carousels by status: {}", status);
        ScanEnhancedRequest request = ScanEnhancedRequest.builder()
                .filterExpression(Expression.builder()
                        .expression("#status = :status")
                        .putExpressionName("#status", "status")
                        .putExpressionValue(":status", AttributeValue.builder().s(status).build())
                        .build())
                .build();

        return carouselTable.scan(request).items().stream().collect(Collectors.toList());
    }

    public List<AdminCarousel> getScheduledCarousels() {
        log.info("Fetching scheduled carousels");
        LocalDateTime now = LocalDateTime.now();
        ScanEnhancedRequest request = ScanEnhancedRequest.builder()
                .filterExpression(Expression.builder()
                        .expression("startDate > :now")
                        .putExpressionValue(":now", AttributeValue.builder().s(now.toString()).build())
                        .build())
                .build();

        return carouselTable.scan(request).items().stream().collect(Collectors.toList());
    }

    public Optional<AdminCarousel> getCarouselById(String id) {
        log.info("Fetching carousel by ID: {}", id);
        AdminCarousel carousel = carouselTable.getItem(Key.builder().partitionValue(id).build());
        return Optional.ofNullable(carousel);
    }

    public AdminCarousel createCarousel(AdminCarousel carousel) {
        log.info("Creating new carousel: {}", carousel.getTitle());

        // Set default values
        carousel.setId(UUID.randomUUID().toString());
        carousel.setCreatedAt(LocalDateTime.now());
        carousel.setUpdatedAt(LocalDateTime.now());

        // Initialize delete status
        if (carousel.getDeleteStatus() == null) {
            carousel.setDeleteStatus(AdminCarousel.DeleteStatus.builder()
                    .isDeleted(false)
                    .restoresCount(0)
                    .build());
        }

        carouselTable.putItem(carousel);
        log.info("Created carousel with ID: {}", carousel.getId());
        return carousel;
    }

    public Optional<AdminCarousel> updateCarousel(String id, AdminCarousel updatedCarousel) {
        log.info("Updating carousel: {}", id);

        Optional<AdminCarousel> existingCarousel = getCarouselById(id);
        if (existingCarousel.isPresent()) {
            AdminCarousel carousel = existingCarousel.get();

            // Update fields
            carousel.setTitle(updatedCarousel.getTitle());
            carousel.setImages(updatedCarousel.getImages());
            carousel.setCtaText(updatedCarousel.getCtaText());
            carousel.setCtaLink(updatedCarousel.getCtaLink());
            carousel.setPriority(updatedCarousel.getPriority());
            carousel.setStartDate(updatedCarousel.getStartDate());
            carousel.setEndDate(updatedCarousel.getEndDate());
            carousel.setStatus(updatedCarousel.getStatus());
            carousel.setType(updatedCarousel.getType());
            carousel.setMetadata(updatedCarousel.getMetadata());
            carousel.setUpdatedAt(LocalDateTime.now());
            carousel.setUpdatedBy(updatedCarousel.getUpdatedBy());

            carouselTable.putItem(carousel);
            log.info("Updated carousel: {}", id);
            return Optional.of(carousel);
        }

        log.warn("Carousel not found for update: {}", id);
        return Optional.empty();
    }

    public boolean softDeleteCarousel(String id, String deletedBy) {
        log.info("Soft deleting carousel: {}", id);

        Optional<AdminCarousel> existingCarousel = getCarouselById(id);
        if (existingCarousel.isPresent()) {
            AdminCarousel carousel = existingCarousel.get();

            // Check if carousel is already deleted
            AdminCarousel.DeleteStatus deleteStatus = carousel.getDeleteStatus();
            if (deleteStatus != null && deleteStatus.getIsDeleted()) {
                log.warn("Carousel is already deleted: {}", id);
                return false;
            }

            if (deleteStatus == null) {
                deleteStatus = AdminCarousel.DeleteStatus.builder().build();
            }

            deleteStatus.setIsDeleted(true);
            deleteStatus.setDeletedAt(LocalDateTime.now());
            deleteStatus.setDeletedBy(deletedBy);

            carousel.setDeleteStatus(deleteStatus);
            carousel.setUpdatedAt(LocalDateTime.now());

            carouselTable.putItem(carousel);
            log.info("Soft deleted carousel: {}", id);
            return true;
        }

        log.warn("Carousel not found for deletion: {}", id);
        return false;
    }

    public boolean restoreCarousel(String id, String restoredBy) {
        log.info("Restoring carousel: {}", id);

        Optional<AdminCarousel> existingCarousel = getCarouselById(id);
        if (existingCarousel.isPresent()) {
            AdminCarousel carousel = existingCarousel.get();

            AdminCarousel.DeleteStatus deleteStatus = carousel.getDeleteStatus();
            if (deleteStatus == null) {
                deleteStatus = AdminCarousel.DeleteStatus.builder().build();
            }

            deleteStatus.setIsDeleted(false);
            deleteStatus.setRestoreAt(LocalDateTime.now());
            deleteStatus.setRestoredBy(restoredBy);
            deleteStatus.setRestoresCount(
                    (deleteStatus.getRestoresCount() != null ? deleteStatus.getRestoresCount() : 0) + 1);

            carousel.setDeleteStatus(deleteStatus);
            carousel.setUpdatedAt(LocalDateTime.now());

            carouselTable.putItem(carousel);
            log.info("Restored carousel: {}", id);
            return true;
        }

        log.warn("Carousel not found for restoration: {}", id);
        return false;
    }

    public boolean updateCarouselStatus(String id, String status, String updatedBy) {
        log.info("Updating carousel status: {} to {}", id, status);

        Optional<AdminCarousel> existingCarousel = getCarouselById(id);
        if (existingCarousel.isPresent()) {
            AdminCarousel carousel = existingCarousel.get();
            carousel.setStatus(status);
            carousel.setUpdatedAt(LocalDateTime.now());
            carousel.setUpdatedBy(updatedBy);

            carouselTable.putItem(carousel);
            log.info("Updated carousel status: {} to {}", id, status);
            return true;
        }

        log.warn("Carousel not found for status update: {}", id);
        return false;
    }
}