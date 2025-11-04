package com.shop.client.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreateOrderRequest {

    @NotEmpty(message = "Order items cannot be empty")
    private List<OrderItemRequest> items;

    @NotNull(message = "Shipping address is required")
    private Long shippingAddressId;

    @NotNull(message = "Billing address is required")
    private Long billingAddressId;

    @NotNull(message = "Payment method is required")
    private String paymentMethod;

    private String notes;
}
