package com.shop.user.dto;

import com.shop.user.enums.UserRole;

/**
 * Response DTO for Cognito user creation
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-21
 */
public class CognitoUserCreationResponse {

    private String username;
    private String temporaryPassword;
    private String email;
    private UserRole group;

    public CognitoUserCreationResponse() {
    }

    public CognitoUserCreationResponse(String username, String temporaryPassword, String email, UserRole group) {
        this.username = username;
        this.temporaryPassword = temporaryPassword;
        this.email = email;
        this.group = group;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getTemporaryPassword() {
        return temporaryPassword;
    }

    public void setTemporaryPassword(String temporaryPassword) {
        this.temporaryPassword = temporaryPassword;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public UserRole getGroup() {
        return group;
    }

    public void setGroup(UserRole group) {
        this.group = group;
    }

    @Override
    public String toString() {
        return "CognitoUserCreationResponse{" +
                "username='" + username + '\'' +
                ", temporaryPassword='" + temporaryPassword + '\'' +
                ", email='" + email + '\'' +
                ", group=" + group +
                '}';
    }
}