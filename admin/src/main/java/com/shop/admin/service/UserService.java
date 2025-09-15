package com.shop.admin.service;

import com.shop.admin.model.AdminUserProfile;
import com.shop.admin.repository.UserProfileRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final UserProfileRepository userProfileRepository;

    public UserService(UserProfileRepository userProfileRepository) {
        this.userProfileRepository = userProfileRepository;
    }

    public List<AdminUserProfile> getAllUsers() {
        return userProfileRepository.getAllUsers();
    }

    public List<AdminUserProfile> getAllUsers(int limit) {
        return userProfileRepository.getAllUsers(limit);
    }
}