package com.shop.auth.repository;

import com.shop.auth.model.User;
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

    private final DynamoDbTable<User> userProfileTable;

    public UserProfileRepository(DynamoDbEnhancedClient enhancedClient,
            @Value("${aws.dynamodb.user-table}") String tableName) {
        this.userProfileTable = enhancedClient.table(tableName, TableSchema.fromBean(User.class));
    }

    public void save(User userProfile) {
        userProfileTable.putItem(userProfile);
    }

    public Optional<User> findByUserId(String userId) {
        Key key = Key.builder().partitionValue(userId).build();
        User item = userProfileTable.getItem(r -> r.key(key));
        return Optional.ofNullable(item);
    }

    public Optional<User> findByUsername(String username) {
        DynamoDbIndex<User> usernameIndex = userProfileTable.index("username-index");

        QueryConditional queryConditional = QueryConditional.keyEqualTo(
                Key.builder().partitionValue(username).build());

        return usernameIndex.query(r -> r.queryConditional(queryConditional))
                .stream()
                .flatMap(page -> page.items().stream())
                .findFirst();
    }

    public Optional<User> findByEmail(String email) {
        DynamoDbIndex<User> emailIndex = userProfileTable.index("email-index");

        QueryConditional queryConditional = QueryConditional.keyEqualTo(
                Key.builder().partitionValue(email).build());

        return emailIndex.query(r -> r.queryConditional(queryConditional))
                .stream()
                .flatMap(page -> page.items().stream())
                .findFirst();
    }

    public void update(User userProfile) {
        userProfileTable.updateItem(userProfile);
    }

    public void delete(String userId) {
        Key key = Key.builder().partitionValue(userId).build();
        userProfileTable.deleteItem(key);
    }
}