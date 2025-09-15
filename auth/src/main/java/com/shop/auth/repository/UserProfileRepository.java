package com.shop.auth.repository;

import com.shop.auth.model.AdminUserProfile;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;

import java.util.Optional;

@Repository
public class UserProfileRepository {

    private final DynamoDbTable<AdminUserProfile> userProfileTable;

    public UserProfileRepository(DynamoDbEnhancedClient enhancedClient,
            @Value("${aws.dynamodb.user-table}") String tableName) {
        this.userProfileTable = enhancedClient.table(tableName, TableSchema.fromBean(AdminUserProfile.class));
    }

    public void save(AdminUserProfile userProfile) {
        userProfileTable.putItem(userProfile);
    }

    public Optional<AdminUserProfile> findByUserId(String userId) {
        Key key = Key.builder().partitionValue(userId).build();
        AdminUserProfile item = userProfileTable.getItem(r -> r.key(key));
        return Optional.ofNullable(item);
    }

    public Optional<AdminUserProfile> findByUsername(String username) {
        DynamoDbIndex<AdminUserProfile> usernameIndex = userProfileTable.index("username-index");

        QueryConditional queryConditional = QueryConditional.keyEqualTo(
                Key.builder().partitionValue(username).build());

        return usernameIndex.query(r -> r.queryConditional(queryConditional))
                .stream()
                .flatMap(page -> page.items().stream())
                .findFirst();
    }

    public Optional<AdminUserProfile> findByEmail(String email) {
        DynamoDbIndex<AdminUserProfile> emailIndex = userProfileTable.index("email-index");

        QueryConditional queryConditional = QueryConditional.keyEqualTo(
                Key.builder().partitionValue(email).build());

        return emailIndex.query(r -> r.queryConditional(queryConditional))
                .stream()
                .flatMap(page -> page.items().stream())
                .findFirst();
    }

    public void update(AdminUserProfile userProfile) {
        userProfileTable.updateItem(userProfile);
    }

    public void delete(String userId) {
        Key key = Key.builder().partitionValue(userId).build();
        userProfileTable.deleteItem(key);
    }
}