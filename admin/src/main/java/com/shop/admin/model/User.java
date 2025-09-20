package com.shop.admin.model;

import com.shop.admin.enums.UserRole;
import com.shop.admin.enums.UserStatus;
import com.shop.admin.enums.FraudRisk;
import com.shop.admin.enums.Theme;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;

import java.time.Instant;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@DynamoDbBean
public class User {

    private String userId; // UUID
    private String username;
    private String custName; // name
    private String email;
    private String phone;
    private String gender; // MALE | FEMALE
    private String profilePicture;
    private Boolean verified;
    private List<Address> addresses;
    private Preferences preferences;
    private AccountStats accountStats;
    private UserRole role; // USER | ADMIN | SUPPORT
    private UserStatus accountStatus; // ACTIVE | INACTIVE | BANNED
    private Boolean kycVerified; // identity verification
    private FraudRisk fraudRisk; // LOW | MEDIUM | HIGH
    private Consent consent; // GDPR/consent flags
    private DeleteStatus deleteStatus; // Soft delete tracking
    private Instant createdAt;
    private Instant updatedAt;
    private Instant lastLogin; // Last successful login timestamp
    private String createdBy; // admin/system
    private String updatedBy; // admin/system
    private Boolean isActive; // quick toggle

    @DynamoDbPartitionKey
    public String getUserId() {
        return userId;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = "username-index")
    public String getUsername() {
        return username;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = "email-index")
    public String getEmail() {
        return email;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class Address {
        private String id;
        private String title;
        private String street;
        private String city;
        private String state;
        private String country;
        private String zipCode;
        private Boolean isDefault;
        private String type; // HOME | WORK | OTHER
        private Coordinates coordinates;

        @Data
        @Builder
        @NoArgsConstructor
        @AllArgsConstructor
        @DynamoDbBean
        public static class Coordinates {
            private Double lat;
            private Double lng;
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class Preferences {
        private Boolean newsletter;
        private Boolean notifications;
        private String language;
        private String currency;
        private Theme theme; // LIGHT | DARK
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class AccountStats {
        private Integer totalOrders;
        private Double totalSpent;
        private List<String> favoriteCategories;
        private Integer wishlistCount;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class Consent {
        private Boolean marketing;
        private Boolean dataSharing;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class DeleteStatus {
        private Boolean isDeleted;
        private Integer restoresCount;
        private Instant deletedAt;
        private Instant restoreAt;

        // Static method to create default deleteStatus
        public static DeleteStatus createDefault() {
            return DeleteStatus.builder()
                    .isDeleted(false)
                    .restoresCount(0)
                    .deletedAt(null)
                    .restoreAt(null)
                    .build();
        }
    }
}