package com.shop.user.dto;

import com.shop.user.enums.UserRole;
import java.util.List;

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
    private List<UserRole> roles;
    private String status;

    public UserCreationResponse() {
    }

    public UserCreationResponse(String userId, String cognitoUsername, String email,
            String temporaryPassword, List<UserRole> roles, String status) {
        this.userId = userId;
        this.cognitoUsername = cognitoUsername;
        this.email = email;
        this.temporaryPassword = temporaryPassword;
        this.roles = roles;
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

    public List<UserRole> getRoles() {
        return roles;
    }

    public void setRoles(List<UserRole> roles) {
        this.roles = roles;
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
                ", roles=" + roles +
                ", status='" + status + '\'' +
                '}';
    }
}