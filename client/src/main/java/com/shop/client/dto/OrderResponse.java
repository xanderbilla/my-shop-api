package com.shop.client.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OrderResponse {

    private Long id;
    private String orderNumber;
    private Long userId;
    private String userEmail;
    private List<OrderItemResponse> items;
    private String status;
    private BigDecimal subtotal;
    private BigDecimal tax;
    private BigDecimal shippingCost;
    private BigDecimal totalAmount;
    private AddressResponse shippingAddress;
    private AddressResponse billingAddress;
    private String paymentMethod;
    private String paymentStatus;
    private String paymentTransactionId;
    private String trackingNumber;
    private LocalDateTime shippedAt;
    private LocalDateTime deliveredAt;
    private String notes;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
