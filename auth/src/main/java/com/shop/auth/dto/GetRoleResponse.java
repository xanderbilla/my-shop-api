package com.shop.auth.dto;

import com.shop.auth.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GetRoleResponse {
    private String username;
    private String email;
    private List<UserRole> roles;
}