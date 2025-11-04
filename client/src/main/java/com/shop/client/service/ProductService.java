package com.shop.client.service;

import com.shop.client.dto.ProductRequest;
import com.shop.client.dto.ProductResponse;
import com.shop.client.model.Product;
import com.shop.client.repository.ProductRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
public class ProductService {

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private ModelMapper modelMapper;

    public Page<ProductResponse> getAllProducts(Pageable pageable) {
        return productRepository.findByActiveTrue(pageable)
                .map(this::convertToResponse);
    }

    public Page<ProductResponse> getProductsByCategory(String category, Pageable pageable) {
        return productRepository.findByActiveTrueAndCategory(category, pageable)
                .map(this::convertToResponse);
    }

    public List<ProductResponse> getFeaturedProducts() {
        return productRepository.findByFeaturedTrueAndActiveTrue()
                .stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    public Page<ProductResponse> searchProducts(String searchTerm, Pageable pageable) {
        return productRepository.searchProducts(searchTerm, pageable)
                .map(this::convertToResponse);
    }

    public ProductResponse getProductById(Long id) {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found with id: " + id));
        return convertToResponse(product);
    }

    public ProductResponse createProduct(ProductRequest request) {
        Product product = modelMapper.map(request, Product.class);
        product.setActive(true);
        product = productRepository.save(product);
        return convertToResponse(product);
    }

    public ProductResponse updateProduct(Long id, ProductRequest request) {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found with id: " + id));

        modelMapper.map(request, product);
        product = productRepository.save(product);
        return convertToResponse(product);
    }

    public void deleteProduct(Long id) {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found with id: " + id));
        product.setActive(false);
        productRepository.save(product);
    }

    private ProductResponse convertToResponse(Product product) {
        return modelMapper.map(product, ProductResponse.class);
    }
}
