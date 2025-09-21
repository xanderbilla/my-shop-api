package com.shop.auth.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.shop.auth.enums.UserRole;
import com.shop.auth.enums.CognitoUserStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.ArrayList;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthUser {
    private String userId; // Cognito UUID
    private String username; // User-friendly username
    private String name;
    private String email;

    @JsonProperty("enabled")
    private boolean enabled; // Maps to Cognito enabled field
    private List<UserRole> roles;
    @JsonProperty("userStatus")
    private CognitoUserStatus userStatus; // Maps to Cognito user status (UNCONFIRMED, CONFIRMED, etc.)

    // Constructor for creating user without roles (defaults to USER)
    public AuthUser(String userId, String username, String name, String email, boolean enabled) {
        this.userId = userId;
        this.username = username;
        this.name = name;
        this.email = email;
        this.enabled = enabled;
        this.roles = new ArrayList<>();
        this.roles.add(UserRole.USER);
        this.userStatus = CognitoUserStatus.UNCONFIRMED; // Default status
    }

    // Helper method to check if user has a specific role
    public boolean hasRole(UserRole role) {
        return roles != null && roles.contains(role);
    }

    // Helper method to add a role
    public void addRole(UserRole role) {
        if (roles == null) {
            roles = new ArrayList<>();
        }
        if (!roles.contains(role)) {
            roles.add(role);
        }
    }

    // Helper method to remove a role
    public void removeRole(UserRole role) {
        if (roles != null) {
            roles.remove(role);
        }
    }
}