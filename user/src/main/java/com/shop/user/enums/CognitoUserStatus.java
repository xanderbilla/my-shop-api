package com.shop.user.enums;

/**
 * Cognito User Status Enum
 * 
 * Represents the user status in AWS Cognito User Pool
 * This should be kept in sync with AWS Cognito user status
 * 
 * @author Vikas Singh
 * @version 1.0
 * @since 2025-09-21
 * @reference AWS Cognito UserStatusType
 */
public enum CognitoUserStatus {
    UNCONFIRMED, // User created but not confirmed via email/SMS
    CONFIRMED, // User confirmed and can sign in
    ARCHIVED, // User archived, cannot sign in
    COMPROMISED, // User marked as compromised
    UNKNOWN, // User status unknown
    RESET_REQUIRED, // User must reset password
    FORCE_CHANGE_PASSWORD // User must change password on next sign in
}