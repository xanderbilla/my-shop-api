# Spring Microservices Shop Application

A microservices-based e-commerce application built with Spring Boot and Spring Cloud.

## Architecture Overview

This project consists of multiple microservices that work together to provide a complete e-commerce solution:

- **Service Registry (Eureka Server)** - Service discovery and registration
- **API Gateway** - Single entry point for all client requests
- **Auth Service** - Authentication and authorization
- **Admin Service** - Administrative operations
- **Client Service** - Customer-facing operations

## Services

### 🔧 Service Registry
- **Port**: 8761
- **Purpose**: Eureka server for service discovery
- **URL**: http://localhost:8761

### 🚪 API Gateway
- **Port**: 8080
- **Purpose**: Routes requests to appropriate microservices
- **URL**: http://localhost:8080

### 🔐 Auth Service
- **Port**: 8081 (configurable)
- **Purpose**: Handle authentication and authorization
- **Endpoints**:
  - `GET /auth/info` - Service health check

### 👑 Admin Service
- **Port**: 8082 (configurable)
- **Purpose**: Administrative operations and management

### 👤 Client Service
- **Port**: 8083 (configurable)
- **Purpose**: Customer-facing operations and user management

## Prerequisites

- Java 17 or higher
- Maven 3.6+
- Git

## Getting Started

### 1. Clone the repository
```bash
git clone <repository-url>
cd spring-microservice
```

### 2. Build all services
```bash
# Build all services at once
mvn clean install

# Or build each service individually
cd service-registry && mvn clean install
cd ../api-gateway && mvn clean install
cd ../auth && mvn clean install
cd ../admin && mvn clean install
cd ../client && mvn clean install
```

### 3. Start the services

**Important**: Start services in the following order:

1. **Service Registry** (must be started first)
```bash
cd service-registry
mvn spring-boot:run
```

2. **API Gateway**
```bash
cd api-gateway
mvn spring-boot:run
```

3. **Other Services** (can be started in any order)
```bash
# Auth Service
cd auth
mvn spring-boot:run

# Admin Service
cd admin
mvn spring-boot:run

# Client Service
cd client
mvn spring-boot:run
```

## Configuration

### Service Registry (Eureka)
- Dashboard: http://localhost:8761
- All other services register themselves with this registry

### API Gateway
- All external requests should go through the gateway at http://localhost:8080
- Routes are configured to forward requests to appropriate services

### Service-specific Configuration
Each service has its own `application.properties` file in `src/main/resources/`:
- Database configurations
- Service-specific ports
- Eureka client settings

## API Endpoints

### Auth Service
```
GET /auth/info - Get service information
```

### Gateway Routes
All services are accessible through the gateway:
```
http://localhost:8080/auth/info
http://localhost:8080/admin/{endpoint}
http://localhost:8080/client/{endpoint}
```

## Development

### Adding New Endpoints
1. Create controllers in the appropriate service
2. Ensure proper service registration with Eureka
3. Update API Gateway routes if needed

### Service Communication
Services communicate with each other through:
- Service discovery via Eureka
- Load balancing through Spring Cloud LoadBalancer
- API Gateway routing

## Monitoring

- **Eureka Dashboard**: http://localhost:8761 - View all registered services
- **Service Health**: Each service provides actuator endpoints for monitoring

## Docker Support (Future Enhancement)

```bash
# Build Docker images
docker-compose build

# Start all services
docker-compose up
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Technology Stack

- **Spring Boot** - Microservice framework
- **Spring Cloud** - Microservice coordination
- **Spring Cloud Gateway** - API Gateway
- **Netflix Eureka** - Service discovery
- **Maven** - Build tool
- **Java 17** - Programming language

## Troubleshooting

### Common Issues

1. **Service not registering with Eureka**
   - Ensure Service Registry is running first
   - Check `eureka.client.service-url.defaultZone` configuration

2. **Gateway not routing requests**
   - Verify service registration in Eureka dashboard
   - Check gateway route configurations

3. **Port conflicts**
   - Update `server.port` in `application.properties`
   - Ensure no other applications are using the same ports

## License

This project is licensed under the MIT License - see the LICENSE file for details.


- it still disply uuid in usernma while login and veirfy otp
- and when we use /me it should display information about current logged in user so we should not pass username in params or in anyway
- add endpoint to get role and update role. A user cam have multiple roles and roles can be updated by only the user who have ADMIN role.
- add an endpoint called /change-password that used by loggedin user so he can change passowrd by entering current pass and new pass without any otp