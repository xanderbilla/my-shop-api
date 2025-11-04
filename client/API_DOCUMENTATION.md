# E-Commerce Client Service API Documentation

A comprehensive Spring Boot microservice for e-commerce client operations with authentication, product management, shopping cart, orders, and address management.

## Features

- ✅ User Authentication (Register/Login) with JWT
- ✅ Product Management (CRUD operations)
- ✅ Shopping Cart functionality
- ✅ Order Management
- ✅ Address Management
- ✅ Search and Filter Products
- ✅ Pagination and Sorting
- ✅ Role-based Access Control
- ✅ RESTful API Design

## Tech Stack

- Java 21
- Spring Boot 3.5.5
- Spring Data JPA
- Spring Security
- JWT (JSON Web Tokens)
- H2 Database (Development)
- PostgreSQL (Production Ready)
- Lombok
- ModelMapper
- Maven

## API Endpoints

### Authentication APIs

#### Register New User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "firstName": "John",
  "lastName": "Doe",
  "phone": "+1234567890"
}

Response:
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "type": "Bearer",
  "userId": 1,
  "email": "user@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "role": "CUSTOMER"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}

Response: Same as register
```

### Product APIs

#### Get All Products (with Pagination)
```http
GET /api/products?page=0&size=20&sortBy=id&sortDirection=DESC

Response:
{
  "content": [...],
  "totalElements": 100,
  "totalPages": 5,
  "size": 20,
  "number": 0
}
```

#### Get Single Product
```http
GET /api/products/{id}

Response:
{
  "id": 1,
  "name": "Product Name",
  "description": "Product Description",
  "price": 99.99,
  "discountPrice": 79.99,
  "stockQuantity": 100,
  "sku": "PROD-001",
  "brand": "Brand Name",
  "category": "Electronics",
  "images": ["url1", "url2"],
  "active": true,
  "featured": false,
  "rating": 4.5,
  "reviewCount": 120,
  "createdAt": "2024-11-04T10:00:00",
  "updatedAt": "2024-11-04T10:00:00"
}
```

#### Get Products by Category
```http
GET /api/products/category/{category}?page=0&size=20
```

#### Get Featured Products
```http
GET /api/products/featured
```

#### Search Products
```http
GET /api/products/search?query=laptop&page=0&size=20
```

#### Create Product (Admin Only)
```http
POST /api/products
Authorization: Bearer {token}
Content-Type: application/json

{
  "name": "Product Name",
  "description": "Product Description",
  "price": 99.99,
  "discountPrice": 79.99,
  "stockQuantity": 100,
  "sku": "PROD-001",
  "brand": "Brand Name",
  "category": "Electronics",
  "images": ["url1", "url2"],
  "featured": false
}
```

#### Update Product (Admin Only)
```http
PUT /api/products/{id}
Authorization: Bearer {token}
Content-Type: application/json

{...same as create}
```

#### Delete Product (Admin Only)
```http
DELETE /api/products/{id}
Authorization: Bearer {token}
```

### Cart APIs

#### Get Cart
```http
GET /api/cart
Authorization: Bearer {token}

Response:
{
  "id": 1,
  "userId": 1,
  "items": [
    {
      "id": 1,
      "productId": 1,
      "productName": "Product Name",
      "productPrice": 99.99,
      "productImage": "url",
      "quantity": 2,
      "subtotal": 199.98
    }
  ],
  "totalAmount": 199.98,
  "totalItems": 2
}
```

#### Add to Cart
```http
POST /api/cart/items
Authorization: Bearer {token}
Content-Type: application/json

{
  "productId": 1,
  "quantity": 2
}
```

#### Update Cart Item
```http
PUT /api/cart/items/{productId}?quantity=3
Authorization: Bearer {token}
```

#### Remove from Cart
```http
DELETE /api/cart/items/{productId}
Authorization: Bearer {token}
```

#### Clear Cart
```http
DELETE /api/cart
Authorization: Bearer {token}
```

### Order APIs

#### Get All Orders
```http
GET /api/orders?page=0&size=10
Authorization: Bearer {token}

Response:
{
  "content": [
    {
      "id": 1,
      "orderNumber": "ORD-12345678",
      "userId": 1,
      "userEmail": "user@example.com",
      "items": [...],
      "status": "PENDING",
      "subtotal": 199.98,
      "tax": 19.99,
      "shippingCost": 10.00,
      "totalAmount": 229.97,
      "shippingAddress": {...},
      "billingAddress": {...},
      "paymentMethod": "CREDIT_CARD",
      "paymentStatus": "PENDING",
      "createdAt": "2024-11-04T10:00:00",
      "updatedAt": "2024-11-04T10:00:00"
    }
  ],
  "totalElements": 10,
  "totalPages": 1
}
```

#### Get Single Order
```http
GET /api/orders/{id}
Authorization: Bearer {token}
```

#### Create Order
```http
POST /api/orders
Authorization: Bearer {token}
Content-Type: application/json

{
  "items": [
    {
      "productId": 1,
      "quantity": 2
    }
  ],
  "shippingAddressId": 1,
  "billingAddressId": 1,
  "paymentMethod": "CREDIT_CARD",
  "notes": "Please deliver before 5 PM"
}
```

#### Update Order Status
```http
PUT /api/orders/{id}/status?status=SHIPPED
Authorization: Bearer {token}
```

#### Cancel Order
```http
DELETE /api/orders/{id}
Authorization: Bearer {token}
```

### Address APIs

#### Get All Addresses
```http
GET /api/addresses
Authorization: Bearer {token}

Response:
[
  {
    "id": 1,
    "fullName": "John Doe",
    "addressLine1": "123 Main St",
    "addressLine2": "Apt 4B",
    "city": "New York",
    "state": "NY",
    "country": "USA",
    "postalCode": "10001",
    "phone": "+1234567890",
    "type": "HOME",
    "isDefault": true
  }
]
```

#### Get Single Address
```http
GET /api/addresses/{id}
Authorization: Bearer {token}
```

#### Create Address
```http
POST /api/addresses
Authorization: Bearer {token}
Content-Type: application/json

{
  "fullName": "John Doe",
  "addressLine1": "123 Main St",
  "addressLine2": "Apt 4B",
  "city": "New York",
  "state": "NY",
  "country": "USA",
  "postalCode": "10001",
  "phone": "+1234567890",
  "type": "HOME",
  "isDefault": true
}
```

#### Update Address
```http
PUT /api/addresses/{id}
Authorization: Bearer {token}
Content-Type: application/json

{...same as create}
```

#### Delete Address
```http
DELETE /api/addresses/{id}
Authorization: Bearer {token}
```

## Order Status Values
- `PENDING` - Order created, awaiting confirmation
- `CONFIRMED` - Order confirmed
- `PROCESSING` - Order being prepared
- `SHIPPED` - Order shipped
- `DELIVERED` - Order delivered
- `CANCELLED` - Order cancelled
- `RETURNED` - Order returned

## Payment Methods
- `CREDIT_CARD`
- `DEBIT_CARD`
- `PAYPAL`
- `STRIPE`
- `CASH_ON_DELIVERY`

## Payment Status
- `PENDING` - Payment pending
- `COMPLETED` - Payment successful
- `FAILED` - Payment failed
- `REFUNDED` - Payment refunded

## Address Types
- `HOME`
- `OFFICE`
- `OTHER`

## User Roles
- `CUSTOMER` - Regular customer
- `ADMIN` - Administrator with full access
- `VENDOR` - Vendor (future use)

## Running the Application

### Prerequisites
- Java 21
- Maven 3.6+

### Steps

1. **Clone the repository**
```bash
cd client
```

2. **Build the project**
```bash
mvn clean install
```

3. **Run the application**
```bash
mvn spring-boot:run
```

The application will start on `http://localhost:8084`

4. **Access H2 Console** (Development)
```
URL: http://localhost:8084/h2-console
JDBC URL: jdbc:h2:mem:clientdb
Username: sa
Password: (leave blank)
```

## Testing the APIs

### Using cURL

**Register:**
```bash
curl -X POST http://localhost:8084/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "firstName": "Test",
    "lastName": "User",
    "phone": "+1234567890"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:8084/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

**Get Products:**
```bash
curl -X GET http://localhost:8084/api/products
```

**Get Cart (Authenticated):**
```bash
curl -X GET http://localhost:8084/api/cart \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Database Schema

The application uses JPA to auto-generate the following tables:
- `users` - User information
- `products` - Product catalog
- `orders` - Customer orders
- `order_items` - Order line items
- `carts` - Shopping carts
- `cart_items` - Cart items
- `addresses` - Shipping/billing addresses

## Security

- JWT-based authentication
- Password encryption using BCrypt
- Role-based access control
- CORS enabled for cross-origin requests
- Session management: STATELESS

## Configuration

Key configuration properties in `application.properties`:

```properties
# Server
server.port=8084

# Database (H2)
spring.datasource.url=jdbc:h2:mem:clientdb

# JWT
jwt.secret=your-secret-key
jwt.expiration=86400000

# Eureka
eureka.client.service-url.defaultZone=http://localhost:8761/eureka/
```

## Production Configuration

For production, update to use PostgreSQL:

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/clientdb
spring.datasource.username=your-username
spring.datasource.password=your-password
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=validate
```

## Error Handling

All endpoints return appropriate HTTP status codes:
- `200 OK` - Successful request
- `201 Created` - Resource created
- `204 No Content` - Successful deletion
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Missing or invalid token
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

## Future Enhancements

- Payment gateway integration
- Email notifications
- Order tracking
- Product reviews and ratings
- Wishlist functionality
- Coupon/discount codes
- Advanced search filters
- Product recommendations
- Image upload functionality

## License

This project is part of a microservices architecture for an e-commerce platform.

## Contact

For issues or questions, please contact the development team.
