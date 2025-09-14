package com.shop.auth.model;

import com.shop.auth.enums.UserRole;

public class User {
    private String username;
    private String name;
    private String email;
    private boolean isVerified;
    private UserRole role;

    // Default constructor
    public User() {
    }

    // Constructor for creating user without role (defaults to USER)
    public User(String username, String name, String email, boolean isVerified) {
        this.username = username;
        this.name = name;
        this.email = email;
        this.isVerified = isVerified;
        this.role = UserRole.USER;
    }

    // All-args constructor
    public User(String username, String name, String email, boolean isVerified, UserRole role) {
        this.username = username;
        this.name = name;
        this.email = email;
        this.isVerified = isVerified;
        this.role = role;
    }

    // Getters
    public String getUsername() {
        return username;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public boolean isVerified() {
        return isVerified;
    }

    public UserRole getRole() {
        return role;
    }

    // Setters
    public void setUsername(String username) {
        this.username = username;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setVerified(boolean verified) {
        isVerified = verified;
    }

    public void setRole(UserRole role) {
        this.role = role;
    }

    // Builder pattern
    public static UserBuilder builder() {
        return new UserBuilder();
    }

    public static class UserBuilder {
        private String username;
        private String name;
        private String email;
        private boolean isVerified;
        private UserRole role;

        public UserBuilder username(String username) {
            this.username = username;
            return this;
        }

        public UserBuilder name(String name) {
            this.name = name;
            return this;
        }

        public UserBuilder email(String email) {
            this.email = email;
            return this;
        }

        public UserBuilder isVerified(boolean isVerified) {
            this.isVerified = isVerified;
            return this;
        }

        public UserBuilder role(UserRole role) {
            this.role = role;
            return this;
        }

        public User build() {
            return new User(username, name, email, isVerified, role);
        }
    }
}