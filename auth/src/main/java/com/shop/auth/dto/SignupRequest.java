package com.shop.auth.dto;

import com.shop.auth.enums.UserRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Arrays;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequest {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z][a-zA-Z0-9_-]*$", message = "Username must start with a letter and can only contain letters, numbers, underscores, and hyphens")
    private String username;

    @NotBlank(message = "Name is required")
    @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
    private String name;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    private String password;

    // Optional roles, defaults to USER if not provided
    // Can accept single role or comma-separated roles: "USER" or "USER,ADMIN"
    private List<UserRole> roles;

    public List<UserRole> getRoles() {
        if (roles == null || roles.isEmpty()) {
            return Arrays.asList(UserRole.USER);
        }
        return roles;
    }

    // For backward compatibility, support single role
    @Deprecated
    public UserRole getRole() {
        List<UserRole> rolesList = getRoles();
        return rolesList.isEmpty() ? UserRole.USER : rolesList.get(0);
    }

    // For backward compatibility, support setting single role
    @Deprecated
    public void setRole(UserRole role) {
        this.roles = role != null ? Arrays.asList(role) : Arrays.asList(UserRole.USER);
    }
}