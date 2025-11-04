package com.shop.client.service;

import com.shop.client.dto.AddressRequest;
import com.shop.client.dto.AddressResponse;
import com.shop.client.model.Address;
import com.shop.client.model.User;
import com.shop.client.repository.AddressRepository;
import com.shop.client.repository.UserRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
public class AddressService {

    @Autowired
    private AddressRepository addressRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ModelMapper modelMapper;

    public List<AddressResponse> getUserAddresses(Long userId) {
        return addressRepository.findByUserId(userId).stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    public AddressResponse getAddressById(Long addressId, Long userId) {
        Address address = addressRepository.findByIdAndUserId(addressId, userId)
                .orElseThrow(() -> new RuntimeException("Address not found"));
        return convertToResponse(address);
    }

    public AddressResponse createAddress(Long userId, AddressRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Address address = modelMapper.map(request, Address.class);
        address.setUser(user);

        if (request.getType() != null) {
            address.setType(Address.AddressType.valueOf(request.getType()));
        }

        // If this is the first address or marked as default, make it default
        if (request.getIsDefault() != null && request.getIsDefault()) {
            // Remove default from other addresses
            addressRepository.findByUserIdAndIsDefaultTrue(userId)
                    .ifPresent(defaultAddress -> {
                        defaultAddress.setIsDefault(false);
                        addressRepository.save(defaultAddress);
                    });
        }

        address = addressRepository.save(address);
        return convertToResponse(address);
    }

    public AddressResponse updateAddress(Long addressId, Long userId, AddressRequest request) {
        Address address = addressRepository.findByIdAndUserId(addressId, userId)
                .orElseThrow(() -> new RuntimeException("Address not found"));

        modelMapper.map(request, address);

        if (request.getType() != null) {
            address.setType(Address.AddressType.valueOf(request.getType()));
        }

        if (request.getIsDefault() != null && request.getIsDefault()) {
            // Remove default from other addresses
            addressRepository.findByUserIdAndIsDefaultTrue(userId)
                    .ifPresent(defaultAddress -> {
                        if (!defaultAddress.getId().equals(addressId)) {
                            defaultAddress.setIsDefault(false);
                            addressRepository.save(defaultAddress);
                        }
                    });
        }

        address = addressRepository.save(address);
        return convertToResponse(address);
    }

    public void deleteAddress(Long addressId, Long userId) {
        Address address = addressRepository.findByIdAndUserId(addressId, userId)
                .orElseThrow(() -> new RuntimeException("Address not found"));
        addressRepository.delete(address);
    }

    private AddressResponse convertToResponse(Address address) {
        AddressResponse response = modelMapper.map(address, AddressResponse.class);
        if (address.getType() != null) {
            response.setType(address.getType().name());
        }
        return response;
    }
}
