package com.shop.auth.model;

import com.shop.auth.enums.UserRole;
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
public class User {
    private String userId; // Cognito UUID
    private String username; // User-friendly username
    private String name;
    private String email;
    private boolean isVerified;
    private List<UserRole> roles;

    // Constructor for creating user without roles (defaults to USER)
    public User(String userId, String username, String name, String email, boolean isVerified) {
        this.userId = userId;
        this.username = username;
        this.name = name;
        this.email = email;
        this.isVerified = isVerified;
        this.roles = new ArrayList<>();
        this.roles.add(UserRole.USER);
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