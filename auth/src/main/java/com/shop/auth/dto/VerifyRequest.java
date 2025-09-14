package com.shop.auth.dto;

import jakarta.validation.constraints.NotBlank;

public class VerifyRequest {

    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Verification code is required")
    private String verificationCode;

    // Default constructor
    public VerifyRequest() {
    }

    // All-args constructor
    public VerifyRequest(String username, String verificationCode) {
        this.username = username;
        this.verificationCode = verificationCode;
    }

    // Getters
    public String getUsername() {
        return username;
    }

    public String getVerificationCode() {
        return verificationCode;
    }

    // Setters
    public void setUsername(String username) {
        this.username = username;
    }

    public void setVerificationCode(String verificationCode) {
        this.verificationCode = verificationCode;
    }
}