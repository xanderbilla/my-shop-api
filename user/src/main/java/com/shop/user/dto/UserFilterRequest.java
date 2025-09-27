package com.shop.user.dto;

import com.shop.user.enums.UserRole;
import com.shop.user.enums.CognitoUserStatus;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;

/**
 * Request DTO for filtering and paginating users
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-27
 */
public class UserFilterRequest {

    // Filter fields
    private String query; // Search by full/partial username, custName, email, phone match
    private CognitoUserStatus userStatus = CognitoUserStatus.CONFIRMED; // Default CONFIRMED
    private UserRole role = UserRole.USER; // Default USER

    // Pagination fields
    @Min(value = 1, message = "Page must be greater than 0")
    private Integer page = 1;

    @Min(value = 1, message = "Limit must be greater than 0")
    private Integer limit = 10;

    // Sort fields
    @Pattern(regexp = "^(createdAt|updatedAt|lastLogin)$", message = "Sort by must be 'createdAt', 'updatedAt', or 'lastLogin'")
    private String sortBy = "createdAt"; // Default sort by creation date

    @Pattern(regexp = "^(asc|desc)$", message = "Sort order must be 'asc' or 'desc'")
    private String sortOrder = "asc"; // Default sort order

    // Constructors
    public UserFilterRequest() {
    }

    public UserFilterRequest(String query, CognitoUserStatus userStatus, UserRole role, Integer page, Integer limit,
            String sortBy, String sortOrder) {
        this.query = query;
        this.userStatus = userStatus != null ? userStatus : CognitoUserStatus.CONFIRMED;
        this.role = role != null ? role : UserRole.USER;
        this.page = page != null ? page : 1;
        this.limit = limit != null ? limit : 10;
        this.sortBy = sortBy != null ? sortBy : "createdAt";
        this.sortOrder = sortOrder != null ? sortOrder : "asc";
    }

    // Getters and Setters
    public String getQuery() {
        return query;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public CognitoUserStatus getUserStatus() {
        return userStatus;
    }

    public void setUserStatus(CognitoUserStatus userStatus) {
        this.userStatus = userStatus != null ? userStatus : CognitoUserStatus.CONFIRMED;
    }

    public UserRole getRole() {
        return role;
    }

    public void setRole(UserRole role) {
        this.role = role != null ? role : UserRole.USER;
    }

    public Integer getPage() {
        return page;
    }

    public void setPage(Integer page) {
        this.page = page != null ? page : 1;
    }

    public Integer getLimit() {
        return limit;
    }

    public void setLimit(Integer limit) {
        this.limit = limit != null ? limit : 10;
    }

    public String getSortBy() {
        return sortBy;
    }

    public void setSortBy(String sortBy) {
        this.sortBy = sortBy != null ? sortBy : "createdAt";
    }

    public String getSortOrder() {
        return sortOrder;
    }

    public void setSortOrder(String sortOrder) {
        this.sortOrder = sortOrder != null ? sortOrder : "asc";
    }

    // Helper method to get offset for pagination
    public int getOffset() {
        return (getPage() - 1) * getLimit();
    }

    @Override
    public String toString() {
        return "UserFilterRequest{" +
                "query='" + query + '\'' +
                ", userStatus=" + userStatus +
                ", role=" + role +
                ", page=" + page +
                ", limit=" + limit +
                ", sortBy='" + sortBy + '\'' +
                ", sortOrder='" + sortOrder + '\'' +
                '}';
    }
}