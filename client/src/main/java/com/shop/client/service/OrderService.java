package com.shop.client.service;

import com.shop.client.dto.*;
import com.shop.client.model.*;
import com.shop.client.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
public class OrderService {

    @Autowired
    private OrderRepository orderRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private AddressRepository addressRepository;

    public Page<OrderResponse> getUserOrders(Long userId, Pageable pageable) {
        return orderRepository.findByUserId(userId, pageable)
                .map(this::convertToResponse);
    }

    public OrderResponse getOrderById(Long orderId, Long userId) {
        Order order = orderRepository.findByIdAndUserId(orderId, userId)
                .orElseThrow(() -> new RuntimeException("Order not found"));
        return convertToResponse(order);
    }

    public OrderResponse createOrder(Long userId, CreateOrderRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Address shippingAddress = addressRepository.findByIdAndUserId(request.getShippingAddressId(), userId)
                .orElseThrow(() -> new RuntimeException("Shipping address not found"));

        Address billingAddress = addressRepository.findByIdAndUserId(request.getBillingAddressId(), userId)
                .orElseThrow(() -> new RuntimeException("Billing address not found"));

        // Create order
        Order order = Order.builder()
                .orderNumber(generateOrderNumber())
                .user(user)
                .status(Order.OrderStatus.PENDING)
                .shippingAddress(shippingAddress)
                .billingAddress(billingAddress)
                .paymentMethod(Order.PaymentMethod.valueOf(request.getPaymentMethod()))
                .paymentStatus(Order.PaymentStatus.PENDING)
                .notes(request.getNotes())
                .build();

        // Create order items
        List<OrderItem> orderItems = new ArrayList<>();
        BigDecimal subtotal = BigDecimal.ZERO;

        for (OrderItemRequest itemRequest : request.getItems()) {
            Product product = productRepository.findById(itemRequest.getProductId())
                    .orElseThrow(() -> new RuntimeException("Product not found: " + itemRequest.getProductId()));

            if (product.getStockQuantity() < itemRequest.getQuantity()) {
                throw new RuntimeException("Insufficient stock for product: " + product.getName());
            }

            BigDecimal price = product.getDiscountPrice() != null ? product.getDiscountPrice() : product.getPrice();
            BigDecimal itemSubtotal = price.multiply(BigDecimal.valueOf(itemRequest.getQuantity()));

            OrderItem orderItem = OrderItem.builder()
                    .order(order)
                    .product(product)
                    .quantity(itemRequest.getQuantity())
                    .price(price)
                    .subtotal(itemSubtotal)
                    .build();

            orderItems.add(orderItem);
            subtotal = subtotal.add(itemSubtotal);

            // Update product stock
            product.setStockQuantity(product.getStockQuantity() - itemRequest.getQuantity());
            productRepository.save(product);
        }

        order.setOrderItems(orderItems);
        order.setSubtotal(subtotal);
        order.setTax(subtotal.multiply(BigDecimal.valueOf(0.1))); // 10% tax
        order.setShippingCost(BigDecimal.valueOf(10)); // Fixed shipping cost
        order.setTotalAmount(subtotal.add(order.getTax()).add(order.getShippingCost()));

        order = orderRepository.save(order);
        return convertToResponse(order);
    }

    public OrderResponse updateOrderStatus(Long orderId, Long userId, String status) {
        Order order = orderRepository.findByIdAndUserId(orderId, userId)
                .orElseThrow(() -> new RuntimeException("Order not found"));

        order.setStatus(Order.OrderStatus.valueOf(status));

        if (status.equals("SHIPPED")) {
            order.setShippedAt(LocalDateTime.now());
        } else if (status.equals("DELIVERED")) {
            order.setDeliveredAt(LocalDateTime.now());
        }

        order = orderRepository.save(order);
        return convertToResponse(order);
    }

    public void cancelOrder(Long orderId, Long userId) {
        Order order = orderRepository.findByIdAndUserId(orderId, userId)
                .orElseThrow(() -> new RuntimeException("Order not found"));

        if (!order.getStatus().equals(Order.OrderStatus.PENDING)) {
            throw new RuntimeException("Only pending orders can be cancelled");
        }

        // Restore product stock
        for (OrderItem item : order.getOrderItems()) {
            Product product = item.getProduct();
            product.setStockQuantity(product.getStockQuantity() + item.getQuantity());
            productRepository.save(product);
        }

        order.setStatus(Order.OrderStatus.CANCELLED);
        orderRepository.save(order);
    }

    private String generateOrderNumber() {
        return "ORD-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }

    private OrderResponse convertToResponse(Order order) {
        List<OrderItemResponse> itemResponses = order.getOrderItems().stream()
                .map(item -> OrderItemResponse.builder()
                        .id(item.getId())
                        .productId(item.getProduct().getId())
                        .productName(item.getProduct().getName())
                        .quantity(item.getQuantity())
                        .price(item.getPrice())
                        .discount(item.getDiscount())
                        .subtotal(item.getSubtotal())
                        .build())
                .collect(Collectors.toList());

        return OrderResponse.builder()
                .id(order.getId())
                .orderNumber(order.getOrderNumber())
                .userId(order.getUser().getId())
                .userEmail(order.getUser().getEmail())
                .items(itemResponses)
                .status(order.getStatus().name())
                .subtotal(order.getSubtotal())
                .tax(order.getTax())
                .shippingCost(order.getShippingCost())
                .totalAmount(order.getTotalAmount())
                .shippingAddress(convertAddressToResponse(order.getShippingAddress()))
                .billingAddress(convertAddressToResponse(order.getBillingAddress()))
                .paymentMethod(order.getPaymentMethod().name())
                .paymentStatus(order.getPaymentStatus().name())
                .paymentTransactionId(order.getPaymentTransactionId())
                .trackingNumber(order.getTrackingNumber())
                .shippedAt(order.getShippedAt())
                .deliveredAt(order.getDeliveredAt())
                .notes(order.getNotes())
                .createdAt(order.getCreatedAt())
                .updatedAt(order.getUpdatedAt())
                .build();
    }

    private AddressResponse convertAddressToResponse(Address address) {
        if (address == null)
            return null;

        return AddressResponse.builder()
                .id(address.getId())
                .fullName(address.getFullName())
                .addressLine1(address.getAddressLine1())
                .addressLine2(address.getAddressLine2())
                .city(address.getCity())
                .state(address.getState())
                .country(address.getCountry())
                .postalCode(address.getPostalCode())
                .phone(address.getPhone())
                .type(address.getType() != null ? address.getType().name() : null)
                .isDefault(address.getIsDefault())
                .build();
    }
}
