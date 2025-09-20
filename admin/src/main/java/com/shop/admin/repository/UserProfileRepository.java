package com.shop.admin.repository;

import com.shop.admin.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.Key;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Repository class for User Profile operations with DynamoDB
 * 
 * Provides data access methods for user management including:
 * - User retrieval (single and multiple)
 * - User updates and soft deletion
 * - Address and role management
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-20
 * @created 2025-09-20
 * @lastModified 2025-09-20
 * 
 * @reference AWS DynamoDB Enhanced Client
 * @reference Spring Boot Framework
 */
@Repository
public class UserProfileRepository {

    private final DynamoDbTable<User> userProfileTable;

    public UserProfileRepository(DynamoDbEnhancedClient enhancedClient,
            @Value("${aws.dynamodb.user-table}") String tableName) {
        this.userProfileTable = enhancedClient.table(tableName, TableSchema.fromBean(User.class));
    }

    /**
     * Retrieves all users from DynamoDB table
     * 
     * @return List of all users
     */
    public List<User> getAllUsers() {
        return userProfileTable.scan(ScanEnhancedRequest.builder().build())
                .items()
                .stream()
                .collect(Collectors.toList());
    }

    /**
     * Retrieves limited number of users from DynamoDB table
     * 
     * @param limit Maximum number of users to retrieve
     * @return List of users up to the specified limit
     */
    public List<User> getAllUsers(int limit) {
        return userProfileTable.scan(ScanEnhancedRequest.builder().limit(limit).build())
                .items()
                .stream()
                .limit(limit)
                .collect(Collectors.toList());
    }

    /**
     * Retrieves a single user by UUID
     * 
     * @param userId The unique identifier of the user
     * @return Optional containing the user if found, empty otherwise
     */
    public Optional<User> getUserById(String userId) {
        try {
            Key key = Key.builder().partitionValue(userId).build();
            User user = userProfileTable.getItem(key);
            return Optional.ofNullable(user);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /**
     * Updates an existing user in DynamoDB
     * 
     * @param user The user object with updated information
     * @return The updated user object
     */
    public User updateUser(User user) {
        userProfileTable.updateItem(user);
        return user;
    }

    /**
     * Saves or updates a user in DynamoDB
     * 
     * @param user The user object to save
     * @return The saved user object
     */
    public User saveUser(User user) {
        userProfileTable.putItem(user);
        return user;
    }
}