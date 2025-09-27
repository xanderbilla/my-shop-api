package com.shop.user.dto;

import com.shop.user.enums.FraudRisk;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for updating user fraud risk level
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateRiskRequest {

    @NotNull(message = "Risk level must be specified. Valid risk levels are: LOW, MEDIUM, HIGH")
    private FraudRisk risk;
}