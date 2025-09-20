package com.shop.auth.dto;

import com.shop.auth.model.AuthUser;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthSuccessResponse {
    private AuthUser user;
    private String message;
    private boolean requiresVerification;
    
    public static AuthSuccessResponse success(AuthUser user, String message) {
        return AuthSuccessResponse.builder()
                .user(user)
                .message(message)
                .requiresVerification(false)
                .build();
    }
    
    public static AuthSuccessResponse requiresVerification(AuthUser user, String message) {
        return AuthSuccessResponse.builder()
                .user(user)
                .message(message)
                .requiresVerification(true)
                .build();
    }
}