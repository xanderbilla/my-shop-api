package com.shop.client.controller;

import com.shop.client.dto.AddressRequest;
import com.shop.client.dto.AddressResponse;
import com.shop.client.service.AddressService;
import com.shop.client.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/addresses")
@CrossOrigin(origins = "*")
public class AddressController {

    @Autowired
    private AddressService addressService;

    @Autowired
    private UserService userService;

    @GetMapping
    public ResponseEntity<List<AddressResponse>> getUserAddresses() {
        Long userId = getCurrentUserId();
        List<AddressResponse> addresses = addressService.getUserAddresses(userId);
        return ResponseEntity.ok(addresses);
    }

    @GetMapping("/{id}")
    public ResponseEntity<AddressResponse> getAddressById(@PathVariable Long id) {
        Long userId = getCurrentUserId();
        AddressResponse address = addressService.getAddressById(id, userId);
        return ResponseEntity.ok(address);
    }

    @PostMapping
    public ResponseEntity<AddressResponse> createAddress(@Valid @RequestBody AddressRequest request) {
        Long userId = getCurrentUserId();
        AddressResponse address = addressService.createAddress(userId, request);
        return ResponseEntity.ok(address);
    }

    @PutMapping("/{id}")
    public ResponseEntity<AddressResponse> updateAddress(
            @PathVariable Long id,
            @Valid @RequestBody AddressRequest request) {

        Long userId = getCurrentUserId();
        AddressResponse address = addressService.updateAddress(id, userId, request);
        return ResponseEntity.ok(address);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteAddress(@PathVariable Long id) {
        Long userId = getCurrentUserId();
        addressService.deleteAddress(id, userId);
        return ResponseEntity.noContent().build();
    }

    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();
        return userService.getUserIdByEmail(email);
    }
}
