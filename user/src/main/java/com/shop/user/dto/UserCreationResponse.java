package com.shop.user.dto;

import com.shop.user.enums.UserRole;

/**
 * Response DTO for user creation
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-21
 */
public class UserCreationResponse {

    private String userId;
    private String cognitoUsername;
    private String email;
    private String temporaryPassword;
    private UserRole role;
    private String status;

    public UserCreationResponse() {
    }

    public UserCreationResponse(String userId, String cognitoUsername, String email,
            String temporaryPassword, UserRole role, String status) {
        this.userId = userId;
        this.cognitoUsername = cognitoUsername;
        this.email = email;
        this.temporaryPassword = temporaryPassword;
        this.role = role;
        this.status = status;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getCognitoUsername() {
        return cognitoUsername;
    }

    public void setCognitoUsername(String cognitoUsername) {
        this.cognitoUsername = cognitoUsername;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getTemporaryPassword() {
        return temporaryPassword;
    }

    public void setTemporaryPassword(String temporaryPassword) {
        this.temporaryPassword = temporaryPassword;
    }

    public UserRole getRole() {
        return role;
    }

    public void setRole(UserRole role) {
        this.role = role;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @Override
    public String toString() {
        return "UserCreationResponse{" +
                "userId='" + userId + '\'' +
                ", cognitoUsername='" + cognitoUsername + '\'' +
                ", email='" + email + '\'' +
                ", temporaryPassword='" + temporaryPassword + '\'' +
                ", role=" + role +
                ", status='" + status + '\'' +
                '}';
    }
}