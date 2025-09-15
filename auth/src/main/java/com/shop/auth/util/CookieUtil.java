package com.shop.auth.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

@Component
public class CookieUtil {

    @Value("${app.cookie.access-token-name:access_token}")
    private String accessTokenCookieName;

    @Value("${app.cookie.refresh-token-name:refresh_token}")
    private String refreshTokenCookieName;

    @Value("${app.cookie.domain:localhost}")
    private String cookieDomain;

    @Value("${app.cookie.max-age:86400}") // 24 hours default
    private int cookieMaxAge;

    @Value("${app.cookie.secure:false}") // Set to true in production with HTTPS
    private boolean cookieSecure;

    /**
     * Set access token cookie
     */
    public void setAccessTokenCookie(HttpServletResponse response, String token) {
        Cookie cookie = createCookie(accessTokenCookieName, token, cookieMaxAge);
        response.addCookie(cookie);
    }

    /**
     * Set refresh token cookie with longer expiration
     */
    public void setRefreshTokenCookie(HttpServletResponse response, String token) {
        Cookie cookie = createCookie(refreshTokenCookieName, token, cookieMaxAge * 7); // 7 days
        response.addCookie(cookie);
    }

    /**
     * Get access token from cookie
     */
    public Optional<String> getAccessTokenFromCookies(HttpServletRequest request) {
        return getCookieValue(request, accessTokenCookieName);
    }

    /**
     * Get refresh token from cookie
     */
    public Optional<String> getRefreshTokenFromCookies(HttpServletRequest request) {
        return getCookieValue(request, refreshTokenCookieName);
    }

    /**
     * Clear authentication cookies
     */
    public void clearAuthCookies(HttpServletResponse response) {
        clearCookie(response, accessTokenCookieName);
        clearCookie(response, refreshTokenCookieName);
    }

    /**
     * Create a secure HTTP-only cookie
     */
    private Cookie createCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true); // Prevents XSS attacks
        cookie.setSecure(cookieSecure); // HTTPS only in production
        cookie.setPath("/"); // Available for all paths
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "Lax"); // CSRF protection
        
        // Set domain only if not localhost (for production)
        if (!cookieDomain.equals("localhost")) {
            cookie.setDomain(cookieDomain);
        }
        
        return cookie;
    }

    /**
     * Clear a specific cookie
     */
    private void clearCookie(HttpServletResponse response, String cookieName) {
        Cookie cookie = new Cookie(cookieName, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(cookieSecure);
        cookie.setPath("/");
        cookie.setMaxAge(0); // Expire immediately
        
        if (!cookieDomain.equals("localhost")) {
            cookie.setDomain(cookieDomain);
        }
        
        response.addCookie(cookie);
    }

    /**
     * Get cookie value by name
     */
    private Optional<String> getCookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }
        
        return Arrays.stream(request.getCookies())
                .filter(cookie -> cookieName.equals(cookie.getName()))
                .map(Cookie::getValue)
                .filter(value -> value != null && !value.trim().isEmpty())
                .findFirst();
    }
}