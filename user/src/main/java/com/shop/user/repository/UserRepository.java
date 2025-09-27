package com.shop.user.repository;

import com.shop.user.model.User;
import com.shop.user.dto.UserFilterRequest;
import com.shop.user.dto.PaginatedResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Comparator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Repository
public class UserRepository {

    private final DynamoDbTable<User> userTable;

    public UserRepository(DynamoDbEnhancedClient enhancedClient,
            @Value("${aws.dynamodb.user-table}") String tableName) {
        this.userTable = enhancedClient.table(tableName, TableSchema.fromBean(User.class));
    }

    /**
     * Retrieves all users from DynamoDB table
     * 
     * @return List of all users
     */
    public List<User> getAllUsers() {
        return userTable.scan(ScanEnhancedRequest.builder().build())
                .items()
                .stream()
                .collect(Collectors.toList());
    }

    /**
     * Get a user by ID
     * 
     * @param userId User ID to retrieve
     * @return Optional containing the user if found
     */
    public Optional<User> getUserById(String userId) {
        try {
            Key key = Key.builder().partitionValue(userId).build();
            User user = userTable.getItem(key);
            return Optional.ofNullable(user);
        } catch (Exception e) {
            System.err.println("Error retrieving user by ID " + userId + ": " + e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Save or update a user
     * 
     * @param user User object to save
     * @return Saved user
     */
    public User saveUser(User user) {
        try {
            userTable.putItem(user);
            return user;
        } catch (Exception e) {
            System.err.println("Error saving user " + user.getUserId() + ": " + e.getMessage());
            throw new RuntimeException("Failed to save user", e);
        }
    }

    /**
     * Check if user exists by ID
     * 
     * @param userId User ID to check
     * @return true if user exists, false otherwise
     */
    public boolean existsById(String userId) {
        return getUserById(userId).isPresent();
    }

    /**
     * Find user by email using email-index
     * 
     * @param email User email to search for
     * @return Optional containing the user if found
     */
    public Optional<User> findByEmail(String email) {
        try {
            QueryConditional queryConditional = QueryConditional.keyEqualTo(
                    Key.builder().partitionValue(email).build());

            QueryEnhancedRequest queryRequest = QueryEnhancedRequest.builder()
                    .queryConditional(queryConditional)
                    .build();

            return userTable.index("email-index").query(queryRequest)
                    .stream()
                    .flatMap(page -> page.items().stream())
                    .findFirst();
        } catch (Exception e) {
            System.err.println("Error finding user by email " + email + ": " + e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Get filtered, sorted, and paginated users
     * 
     * @param filterRequest Filter and pagination parameters
     * @return PaginatedResponse containing filtered users
     */
    public PaginatedResponse<User> getFilteredUsers(UserFilterRequest filterRequest) {
        try {
            // Get all users first (since DynamoDB doesn't support complex filtering)
            List<User> allUsers = userTable.scan(ScanEnhancedRequest.builder().build())
                    .items()
                    .stream()
                    .collect(Collectors.toList());

            // Apply filters
            Stream<User> filteredStream = allUsers.stream();

            // Filter by query (search in username, custName, email, phone)
            if (filterRequest.getQuery() != null && !filterRequest.getQuery().trim().isEmpty()) {
                String queryFilter = filterRequest.getQuery().toLowerCase();
                filteredStream = filteredStream.filter(
                        user -> (user.getUsername() != null && user.getUsername().toLowerCase().contains(queryFilter))
                                ||
                                (user.getCustName() != null && user.getCustName().toLowerCase().contains(queryFilter))
                                ||
                                (user.getEmail() != null && user.getEmail().toLowerCase().contains(queryFilter)) ||
                                (user.getPhone() != null && user.getPhone().toLowerCase().contains(queryFilter)));
            }

            // Filter by userStatus
            if (filterRequest.getUserStatus() != null) {
                filteredStream = filteredStream.filter(user -> user.getUserStatus() == filterRequest.getUserStatus());
            }

            // Filter by role
            if (filterRequest.getRole() != null) {
                filteredStream = filteredStream
                        .filter(user -> user.getRoles() != null && user.getRoles().contains(filterRequest.getRole()));
            }

            // Apply sorting
            Comparator<User> comparator = getComparator(filterRequest.getSortBy(), filterRequest.getSortOrder());
            List<User> sortedUsers = filteredStream.sorted(comparator).collect(Collectors.toList());

            // Calculate pagination
            long totalRecords = sortedUsers.size();
            int offset = filterRequest.getOffset();
            int limit = filterRequest.getLimit();

            // Apply pagination
            List<User> paginatedUsers = sortedUsers.stream()
                    .skip(offset)
                    .limit(limit)
                    .collect(Collectors.toList());

            return PaginatedResponse.of(paginatedUsers, filterRequest.getPage(), limit, totalRecords);

        } catch (Exception e) {
            System.err.println("Error getting filtered users: " + e.getMessage());
            throw new RuntimeException("Failed to retrieve filtered users", e);
        }
    }

    /**
     * Create comparator for sorting users
     * 
     * @param sortBy    Field to sort by
     * @param sortOrder Sort order (asc/desc)
     * @return Comparator for User objects
     */
    private Comparator<User> getComparator(String sortBy, String sortOrder) {
        Comparator<User> comparator;

        switch (sortBy.toLowerCase()) {
            case "updatedat":
                comparator = Comparator
                        .comparing(user -> user.getUpdatedAt() != null ? user.getUpdatedAt() : Instant.MIN);
                break;
            case "lastlogin":
                comparator = Comparator
                        .comparing(user -> user.getLastLogin() != null ? user.getLastLogin() : Instant.MIN);
                break;
            case "createdat":
            default:
                comparator = Comparator
                        .comparing(user -> user.getCreatedAt() != null ? user.getCreatedAt() : Instant.MIN);
                break;
        }

        return "desc".equalsIgnoreCase(sortOrder) ? comparator.reversed() : comparator;
    }
}