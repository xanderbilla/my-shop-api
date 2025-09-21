package com.shop.user.repository;

import com.shop.user.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

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
}