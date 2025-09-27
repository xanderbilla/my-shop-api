package com.shop.user.dto;

import com.shop.user.enums.UserRole;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Request DTO for updating user roles
 * Supports multiple roles for a user
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateRoleRequest {

    @NotEmpty(message = "At least one role must be specified. Valid roles are: USER, ADMIN, SUPPORT")
    private List<UserRole> roles;
}