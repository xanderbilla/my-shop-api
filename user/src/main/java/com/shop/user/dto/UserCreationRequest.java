package com.shop.user.dto;

import com.shop.user.enums.UserRole;

/**
 * Request DTO for user creation
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-21
 */
public class UserCreationRequest {

    private String email;
    private String name;
    private UserRole role;

    public UserCreationRequest() {
    }

    public UserCreationRequest(String email, String name, UserRole role) {
        this.email = email;
        this.name = name;
        this.role = role;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public UserRole getRole() {
        return role;
    }

    public void setRole(UserRole role) {
        this.role = role;
    }

    @Override
    public String toString() {
        return "UserCreationRequest{" +
                "email='" + email + '\'' +
                ", name='" + name + '\'' +
                ", role=" + role +
                '}';
    }
}