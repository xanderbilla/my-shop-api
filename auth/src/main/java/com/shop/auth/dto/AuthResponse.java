package com.shop.auth.dto;

import com.shop.auth.model.AuthUser;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private AuthUser user;
    private String tokenType = "Bearer";

    public AuthResponse(String accessToken, String refreshToken, AuthUser user) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.user = user;
        this.tokenType = "Bearer";
    }
}