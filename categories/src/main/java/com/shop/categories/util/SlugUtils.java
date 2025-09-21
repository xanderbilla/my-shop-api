package com.shop.categories.util;

import org.springframework.stereotype.Component;

import java.text.Normalizer;
import java.util.Locale;

@Component
public class SlugUtils {

    /**
     * Converts a string to a URL-friendly slug
     * Example: "Men's Fashion & Clothing" -> "mens-fashion-clothing"
     * 
     * @param input The string to convert to slug
     * @return A URL-friendly slug
     */
    public static String generateSlug(String input) {
        if (input == null || input.trim().isEmpty()) {
            return "";
        }

        return input
                .trim()
                .toLowerCase(Locale.ENGLISH)
                // Remove accents and diacritics
                .replaceAll("[àáâãäåāăą]", "a")
                .replaceAll("[èéêëēĕę]", "e")
                .replaceAll("[ìíîïīĭį]", "i")
                .replaceAll("[òóôõöøōŏő]", "o")
                .replaceAll("[ùúûüūŭů]", "u")
                .replaceAll("[ÿýŷ]", "y")
                .replaceAll("[ñń]", "n")
                .replaceAll("[çć]", "c")
                .replaceAll("[ß]", "ss")
                .replaceAll("[æ]", "ae")
                .replaceAll("[œ]", "oe")
                // Remove apostrophes, quotes, and similar characters
                .replaceAll("[''`\"]", "")
                // Replace ampersands with "and"
                .replaceAll("&", " and ")
                // Replace any non-alphanumeric characters with spaces
                .replaceAll("[^a-z0-9\\s]", " ")
                // Replace multiple spaces with single space
                .replaceAll("\\s+", " ")
                .trim()
                // Replace spaces with hyphens
                .replaceAll("\\s", "-")
                // Remove multiple consecutive hyphens
                .replaceAll("-+", "-")
                // Remove leading/trailing hyphens
                .replaceAll("^-|-$", "");
    }

    /**
     * Validates if a slug is valid
     * 
     * @param slug The slug to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidSlug(String slug) {
        if (slug == null || slug.trim().isEmpty()) {
            return false;
        }

        // Should only contain lowercase letters, numbers, and hyphens
        // Should not start or end with hyphens
        // Should not have consecutive hyphens
        return slug.matches("^[a-z0-9]+(-[a-z0-9]+)*$");
    }
}