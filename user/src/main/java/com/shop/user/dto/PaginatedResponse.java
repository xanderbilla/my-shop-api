package com.shop.user.dto;

import java.util.List;

/**
 * Generic paginated response wrapper
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-27
 * @param <T> Type of data being paginated
 */
public class PaginatedResponse<T> {

    private List<T> data;
    private int page;
    private int limit;
    private long totalRecords;
    private int totalPages;
    private boolean hasNext;
    private boolean hasPrevious;

    // Constructors
    public PaginatedResponse() {
    }

    public PaginatedResponse(List<T> data, int page, int limit, long totalRecords) {
        this.data = data;
        this.page = page;
        this.limit = limit;
        this.totalRecords = totalRecords;
        this.totalPages = (int) Math.ceil((double) totalRecords / limit);
        this.hasNext = page < totalPages;
        this.hasPrevious = page > 1;
    }

    // Static factory method for easy creation
    public static <T> PaginatedResponse<T> of(List<T> data, int page, int limit, long totalRecords) {
        return new PaginatedResponse<>(data, page, limit, totalRecords);
    }

    // Getters and Setters
    public List<T> getData() {
        return data;
    }

    public void setData(List<T> data) {
        this.data = data;
    }

    public int getPage() {
        return page;
    }

    public void setPage(int page) {
        this.page = page;
        updateNavigationFlags();
    }

    public int getLimit() {
        return limit;
    }

    public void setLimit(int limit) {
        this.limit = limit;
        updateTotalPages();
        updateNavigationFlags();
    }

    public long getTotalRecords() {
        return totalRecords;
    }

    public void setTotalRecords(long totalRecords) {
        this.totalRecords = totalRecords;
        updateTotalPages();
        updateNavigationFlags();
    }

    public int getTotalPages() {
        return totalPages;
    }

    public void setTotalPages(int totalPages) {
        this.totalPages = totalPages;
    }

    public boolean isHasNext() {
        return hasNext;
    }

    public void setHasNext(boolean hasNext) {
        this.hasNext = hasNext;
    }

    public boolean isHasPrevious() {
        return hasPrevious;
    }

    public void setHasPrevious(boolean hasPrevious) {
        this.hasPrevious = hasPrevious;
    }

    // Helper methods
    private void updateTotalPages() {
        this.totalPages = limit > 0 ? (int) Math.ceil((double) totalRecords / limit) : 0;
    }

    private void updateNavigationFlags() {
        this.hasNext = page < totalPages;
        this.hasPrevious = page > 1;
    }

    @Override
    public String toString() {
        return "PaginatedResponse{" +
                "dataSize=" + (data != null ? data.size() : 0) +
                ", page=" + page +
                ", limit=" + limit +
                ", totalRecords=" + totalRecords +
                ", totalPages=" + totalPages +
                ", hasNext=" + hasNext +
                ", hasPrevious=" + hasPrevious +
                '}';
    }
}