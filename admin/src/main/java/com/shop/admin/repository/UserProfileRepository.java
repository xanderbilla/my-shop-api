package com.shop.admin.repository;

import com.shop.admin.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;

import java.util.List;
import java.util.stream.Collectors;

@Repository
public class UserProfileRepository {

    private final DynamoDbTable<User> userProfileTable;

    public UserProfileRepository(DynamoDbEnhancedClient enhancedClient,
            @Value("${aws.dynamodb.user-table}") String tableName) {
        this.userProfileTable = enhancedClient.table(tableName, TableSchema.fromBean(User.class));
    }

    public List<User> getAllUsers() {
        return userProfileTable.scan(ScanEnhancedRequest.builder().build())
                .items()
                .stream()
                .collect(Collectors.toList());
    }

    public List<User> getAllUsers(int limit) {
        return userProfileTable.scan(ScanEnhancedRequest.builder().limit(limit).build())
                .items()
                .stream()
                .limit(limit)
                .collect(Collectors.toList());
    }
}