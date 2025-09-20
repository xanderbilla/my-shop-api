package com.shop.auth.service;

import com.shop.auth.model.User;
import com.shop.auth.model.AuthUser;
import com.shop.auth.enums.Theme;
import com.shop.auth.enums.UserRole;
import com.shop.auth.enums.UserStatus;
import com.shop.auth.enums.FraudRisk;
import com.shop.auth.repository.UserProfileRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;

@Service
public class UserProfileService {

    private final UserProfileRepository userProfileRepository;

    public UserProfileService(UserProfileRepository userProfileRepository) {
        this.userProfileRepository = userProfileRepository;
    }

    public User createUserProfile(AuthUser user) {
        User userProfile = User.builder()
                .userId(user.getUserId())
                .username(user.getUsername())
                .custName(user.getName())
                .email(user.getEmail())
                .phone(null) // Will be updated later by user
                .gender(null) // Will be updated later by user
                .profilePicture(null)
                .verified(user.isVerified())
                .addresses(new ArrayList<>()) // Empty initially
                .preferences(createDefaultPreferences())
                .accountStats(createDefaultAccountStats())
                .role(user.getRoles().isEmpty() ? UserRole.USER : UserRole.valueOf(user.getRoles().get(0).name())) // Use
                                                                                                                   // actual
                                                                                                                   // role
                                                                                                                   // from
                                                                                                                   // Cognito
                .accountStatus(UserStatus.valueOf(user.getStatus().name())) // ACTIVE, INACTIVE, BANNED - maps directly
                .kycVerified(false)
                .fraudRisk(FraudRisk.LOW)
                .consent(createDefaultConsent())
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .lastLogin(null) // Will be set on first login
                .createdBy("SYSTEM")
                .updatedBy("SYSTEM")
                .isActive(true)
                .build();

        userProfileRepository.save(userProfile);
        return userProfile;
    }

    public User getUserProfile(String userId) {
        return userProfileRepository.findByUserId(userId)
                .orElse(null);
    }

    public User getUserProfileByUsername(String username) {
        return userProfileRepository.findByUsername(username)
                .orElse(null);
    }

    public User getUserProfileByEmail(String email) {
        return userProfileRepository.findByEmail(email)
                .orElse(null);
    }

    public void updateUserProfile(User userProfile) {
        userProfile.setUpdatedAt(Instant.now());
        userProfileRepository.update(userProfile);
    }

    public void deleteUserProfile(String userId) {
        userProfileRepository.delete(userId);
    }

    public void updateLastLogin(String userId) {
        User userProfile = getUserProfile(userId);
        if (userProfile != null) {
            userProfile.setLastLogin(Instant.now());
            // Don't update updatedAt for login activity - only for profile data changes
            userProfileRepository.update(userProfile);
        }
    }

    public void updateVerificationStatus(String userId, boolean verified) {
        User userProfile = getUserProfile(userId);
        if (userProfile != null) {
            userProfile.setVerified(verified);
            userProfile.setUpdatedAt(Instant.now());
            userProfileRepository.update(userProfile);
        }
    }

    private User.Preferences createDefaultPreferences() {
        return User.Preferences.builder()
                .newsletter(false)
                .notifications(true)
                .language("en")
                .currency("USD")
                .theme(Theme.LIGHT)
                .build();
    }

    private User.AccountStats createDefaultAccountStats() {
        return User.AccountStats.builder()
                .totalOrders(0)
                .totalSpent(0.0)
                .favoriteCategories(new ArrayList<>())
                .wishlistCount(0)
                .build();
    }

    private User.Consent createDefaultConsent() {
        return User.Consent.builder()
                .marketing(false)
                .dataSharing(false)
                .build();
    }
}