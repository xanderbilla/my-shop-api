# Docker Deployment Guide

This guide explains how to deploy the Spring Microservices application using Docker containers with AWS ECR images.

## Prerequisites

- Docker and Docker Compose installed
- AWS CLI configured with appropriate permissions
- Access to the AWS ECR Public repositories

## ECR Repositories

The application uses the following ECR repositories:

| Service | ECR Repository |
|---------|----------------|
| Service Registry | `public.ecr.aws/k2g9v6r8/spring-microservice/shop-service-registry` |
| API Gateway | `public.ecr.aws/k2g9v6r8/spring-microservice/shop-api-gateway` |
| Auth Service | `public.ecr.aws/k2g9v6r8/spring-microservice/shop-auth` |
| Admin Service | `public.ecr.aws/k2g9v6r8/spring-microservice/shop-admin` |
| Client Service | `public.ecr.aws/k2g9v6r8/spring-microservice/shop-client` |

## Quick Start

### Using the Management Script (Recommended)

1. **Start all services:**
   ```bash
   ./docker-manage.sh start
   ```

2. **Check service status:**
   ```bash
   ./docker-manage.sh status
   ```

3. **View logs:**
   ```bash
   # All services
   ./docker-manage.sh logs
   
   # Specific service
   ./docker-manage.sh logs auth-service
   ```

4. **Stop all services:**
   ```bash
   ./docker-manage.sh stop
   ```

### Manual Commands

1. **Authenticate with ECR:**
   ```bash
   aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws
   ```

2. **Pull images:**
   ```bash
   docker pull public.ecr.aws/k2g9v6r8/spring-microservice/shop-service-registry:latest
   docker pull public.ecr.aws/k2g9v6r8/spring-microservice/shop-api-gateway:latest
   docker pull public.ecr.aws/k2g9v6r8/spring-microservice/shop-auth:latest
   docker pull public.ecr.aws/k2g9v6r8/spring-microservice/shop-admin:latest
   docker pull public.ecr.aws/k2g9v6r8/spring-microservice/shop-client:latest
   ```

3. **Start services:**
   ```bash
   docker-compose up -d
   ```

## Service Ports

| Service | Port | Health Check |
|---------|------|--------------|
| Service Registry | 8761 | http://localhost:8761/actuator/health |
| API Gateway | 8080 | http://localhost:8080/actuator/health |
| Auth Service | 8082 | http://localhost:8082/actuator/health |
| Admin Service | 8083 | http://localhost:8083/actuator/health |
| Client Service | 8084 | http://localhost:8084/actuator/health |

## Service URLs

- **Eureka Dashboard:** http://localhost:8761
- **API Gateway:** http://localhost:8080
- **Auth Service (direct):** http://localhost:8082
- **Admin Service (direct):** http://localhost:8083
- **Client Service (direct):** http://localhost:8084

## API Endpoints

### Through API Gateway
```bash
# Auth Service
curl http://localhost:8080/auth/info
curl http://localhost:8080/auth/actuator/health

# Admin Service
curl http://localhost:8080/admin/info
curl http://localhost:8080/admin/actuator/health

# Client Service
curl http://localhost:8080/client/info
curl http://localhost:8080/client/actuator/health
```

### Direct Service Access
```bash
# Auth Service
curl http://localhost:8082/auth/info
curl http://localhost:8082/actuator/health

# Admin Service
curl http://localhost:8083/admin/info
curl http://localhost:8083/actuator/health

# Client Service
curl http://localhost:8084/client/info
curl http://localhost:8084/actuator/health
```

## Management Script Commands

```bash
# Available commands
./docker-manage.sh {auth|pull|start|stop|status|logs|restart|update}

# Examples
./docker-manage.sh start           # Start all services
./docker-manage.sh logs api-gateway # View API Gateway logs
./docker-manage.sh restart auth-service # Restart auth service
./docker-manage.sh update          # Pull latest images and restart
```

## Troubleshooting

### Common Issues

1. **Authentication Errors:**
   ```bash
   ./docker-manage.sh auth
   ```

2. **Service Not Starting:**
   ```bash
   ./docker-manage.sh logs service-name
   ```

3. **Port Conflicts:**
   - Ensure no other applications are using ports 8080-8084, 8761
   - Stop existing services: `./docker-manage.sh stop`

4. **Outdated Images:**
   ```bash
   ./docker-manage.sh update
   ```

### Health Checks

All services include health checks that verify:
- Service is responding on the correct port
- Actuator health endpoint is accessible
- Service dependencies are available

### Service Dependencies

The services start in the following order:
1. Service Registry (Eureka)
2. API Gateway, Auth Service, Admin Service, Client Service (parallel)

## Environment Variables

The following environment variables are configured for Docker deployment:

- `SPRING_PROFILES_ACTIVE=docker`
- `EUREKA_CLIENT_SERVICE_URL_DEFAULTZONE=http://service-registry:8761/eureka/`

## Scaling

To scale a specific service:
```bash
docker-compose up -d --scale auth-service=3
```

## Monitoring

- **Eureka Dashboard:** Monitor service registration at http://localhost:8761
- **Service Health:** Check individual service health at `/actuator/health`
- **Service Info:** Get service information at `/actuator/info`
- **Metrics:** Access basic metrics at `/actuator/metrics`
