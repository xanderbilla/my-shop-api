package com.shop.auth.dto;

import com.shop.auth.model.User;

public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private User user;
    private String tokenType = "Bearer";

    // Default constructor
    public AuthResponse() {
    }

    // All-args constructor
    public AuthResponse(String accessToken, String refreshToken, User user, String tokenType) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.user = user;
        this.tokenType = tokenType;
    }

    public AuthResponse(String accessToken, String refreshToken, User user) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.user = user;
        this.tokenType = "Bearer";
    }

    // Getters
    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public User getUser() {
        return user;
    }

    public String getTokenType() {
        return tokenType;
    }

    // Setters
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
}