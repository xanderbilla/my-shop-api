package com.shop.client.service;

import com.shop.client.dto.AddToCartRequest;
import com.shop.client.dto.CartItemResponse;
import com.shop.client.dto.CartResponse;
import com.shop.client.model.Cart;
import com.shop.client.model.CartItem;
import com.shop.client.model.Product;
import com.shop.client.model.User;
import com.shop.client.repository.CartItemRepository;
import com.shop.client.repository.CartRepository;
import com.shop.client.repository.ProductRepository;
import com.shop.client.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
public class CartService {

    @Autowired
    private CartRepository cartRepository;

    @Autowired
    private CartItemRepository cartItemRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private UserRepository userRepository;

    public CartResponse getCart(Long userId) {
        Cart cart = getOrCreateCart(userId);
        return convertToResponse(cart);
    }

    public CartResponse addToCart(Long userId, AddToCartRequest request) {
        Cart cart = getOrCreateCart(userId);

        Product product = productRepository.findById(request.getProductId())
                .orElseThrow(() -> new RuntimeException("Product not found"));

        if (product.getStockQuantity() < request.getQuantity()) {
            throw new RuntimeException("Insufficient stock");
        }

        CartItem existingItem = cartItemRepository.findByCartIdAndProductId(cart.getId(), product.getId())
                .orElse(null);

        if (existingItem != null) {
            existingItem.setQuantity(existingItem.getQuantity() + request.getQuantity());
            cartItemRepository.save(existingItem);
        } else {
            CartItem newItem = CartItem.builder()
                    .cart(cart)
                    .product(product)
                    .quantity(request.getQuantity())
                    .build();
            cartItemRepository.save(newItem);
        }

        return convertToResponse(cart);
    }

    public CartResponse updateCartItem(Long userId, Long productId, Integer quantity) {
        Cart cart = getOrCreateCart(userId);

        CartItem cartItem = cartItemRepository.findByCartIdAndProductId(cart.getId(), productId)
                .orElseThrow(() -> new RuntimeException("Cart item not found"));

        if (quantity <= 0) {
            cartItemRepository.delete(cartItem);
        } else {
            cartItem.setQuantity(quantity);
            cartItemRepository.save(cartItem);
        }

        return convertToResponse(cart);
    }

    public CartResponse removeFromCart(Long userId, Long productId) {
        Cart cart = getOrCreateCart(userId);
        cartItemRepository.deleteByCartIdAndProductId(cart.getId(), productId);
        return convertToResponse(cart);
    }

    public void clearCart(Long userId) {
        Cart cart = getOrCreateCart(userId);
        cart.getItems().clear();
        cartRepository.save(cart);
    }

    private Cart getOrCreateCart(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return cartRepository.findByUserId(userId)
                .orElseGet(() -> {
                    Cart newCart = Cart.builder()
                            .user(user)
                            .build();
                    return cartRepository.save(newCart);
                });
    }

    private CartResponse convertToResponse(Cart cart) {
        List<CartItemResponse> items = cart.getItems().stream()
                .map(item -> {
                    Product product = item.getProduct();
                    BigDecimal price = product.getDiscountPrice() != null ? product.getDiscountPrice()
                            : product.getPrice();
                    BigDecimal subtotal = price.multiply(BigDecimal.valueOf(item.getQuantity()));

                    return CartItemResponse.builder()
                            .id(item.getId())
                            .productId(product.getId())
                            .productName(product.getName())
                            .productPrice(price)
                            .productImage(product.getImages().isEmpty() ? null : product.getImages().get(0))
                            .quantity(item.getQuantity())
                            .subtotal(subtotal)
                            .build();
                })
                .collect(Collectors.toList());

        BigDecimal totalAmount = items.stream()
                .map(CartItemResponse::getSubtotal)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        Integer totalItems = items.stream()
                .mapToInt(CartItemResponse::getQuantity)
                .sum();

        return CartResponse.builder()
                .id(cart.getId())
                .userId(cart.getUser().getId())
                .items(items)
                .totalAmount(totalAmount)
                .totalItems(totalItems)
                .build();
    }
}
