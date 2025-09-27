package com.shop.user.dto;

import com.shop.user.enums.UserRole;
import java.util.List;
import java.util.Arrays;

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
    private List<UserRole> roles;

    public UserCreationRequest() {
    }

    public UserCreationRequest(String email, String name, List<UserRole> roles) {
        this.email = email;
        this.name = name;
        this.roles = roles;
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

    public List<UserRole> getRoles() {
        if (roles == null || roles.isEmpty()) {
            return Arrays.asList(UserRole.USER);
        }
        return roles;
    }

    public void setRoles(List<UserRole> roles) {
        this.roles = roles;
    }

    @Override
    public String toString() {
        return "UserCreationRequest{" +
                "email='" + email + '\'' +
                ", name='" + name + '\'' +
                ", roles=" + roles +
                '}';
    }
}