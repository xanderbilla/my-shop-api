package com.shop.client.controller;

import com.shop.client.dto.AddToCartRequest;
import com.shop.client.dto.CartResponse;
import com.shop.client.service.CartService;
import com.shop.client.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/cart")
@CrossOrigin(origins = "*")
public class CartController {

    @Autowired
    private CartService cartService;

    @Autowired
    private UserService userService;

    @GetMapping
    public ResponseEntity<CartResponse> getCart() {
        Long userId = getCurrentUserId();
        CartResponse cart = cartService.getCart(userId);
        return ResponseEntity.ok(cart);
    }

    @PostMapping("/items")
    public ResponseEntity<CartResponse> addToCart(@Valid @RequestBody AddToCartRequest request) {
        Long userId = getCurrentUserId();
        CartResponse cart = cartService.addToCart(userId, request);
        return ResponseEntity.ok(cart);
    }

    @PutMapping("/items/{productId}")
    public ResponseEntity<CartResponse> updateCartItem(
            @PathVariable Long productId,
            @RequestParam Integer quantity) {

        Long userId = getCurrentUserId();
        CartResponse cart = cartService.updateCartItem(userId, productId, quantity);
        return ResponseEntity.ok(cart);
    }

    @DeleteMapping("/items/{productId}")
    public ResponseEntity<CartResponse> removeFromCart(@PathVariable Long productId) {
        Long userId = getCurrentUserId();
        CartResponse cart = cartService.removeFromCart(userId, productId);
        return ResponseEntity.ok(cart);
    }

    @DeleteMapping
    public ResponseEntity<Void> clearCart() {
        Long userId = getCurrentUserId();
        cartService.clearCart(userId);
        return ResponseEntity.noContent().build();
    }

    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();
        return userService.getUserIdByEmail(email);
    }
}
