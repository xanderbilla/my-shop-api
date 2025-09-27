@echo off
echo Setting up environment variables...

REM Load environment variables from .env.local
set AWS_REGION=us-east-1
set AWS_COGNITO_REGION=us-east-1
set AWS_DYNAMODB_USER_TABLE=my-shop-user-table
set AWS_DYNAMODB_CATEGORIES_TABLE=my-shop-categories-table
set AWS_DYNAMODB_CAROUSEL_TABLE=my-shop-carousel-table
set AWS_COGNITO_USER_POOL_ID=us-east-1_XUiJ6h4fg
set AWS_COGNITO_CLIENT_ID=3bgqh0d8lh59na39bco2itco0k
set AWS_COGNITO_CLIENT_SECRET=1sbkknbq7ijv9a4rfgl8ctntdqrh7kl5phmcu3gp3qe7ibopfnrt

REM Eureka Configuration
set EUREKA_CLIENT_SERVICE_URL_DEFAULTZONE=http://localhost:8761/eureka/

REM Service ports
set SERVICE_REGISTRY_PORT=8761
set API_GATEWAY_PORT=8080
set AUTH_SERVICE_PORT=8082
set USER_SERVICE_PORT=8085
set CLIENT_SERVICE_PORT=8084
set CATEGORIES_SERVICE_PORT=8086
set CAROUSEL_SERVICE_PORT=8087

echo Environment variables set.
echo.
echo Starting services in order:
echo 1. Service Registry (Port 8761)
echo 2. API Gateway (Port 8080)  
echo 3. Auth Service (Port 8082)
echo 4. User Service (Port 8085)
echo 5. Client Service (Port 8084)
echo 6. Categories Service (Port 8086)
echo 7. Carousel Service (Port 8087)
echo.

if "%1"=="service-registry" (
    echo Starting Service Registry...
    cd service-registry
    call mvnw.cmd spring-boot:run
) else if "%1"=="api-gateway" (
    echo Starting API Gateway...
    cd api-gateway
    call mvnw.cmd spring-boot:run
) else if "%1"=="auth" (
    echo Starting Auth Service...
    cd auth
    call mvnw.cmd spring-boot:run
) else if "%1"=="user" (
    echo Starting User Service...
    cd user
    call mvnw.cmd spring-boot:run
) else if "%1"=="client" (
    echo Starting Client Service...
    cd client
    call mvnw.cmd spring-boot:run
) else if "%1"=="categories" (
    echo Starting Categories Service...
    cd categories
    call mvnw.cmd spring-boot:run
) else if "%1"=="carousel" (
    echo Starting Carousel Service...
    cd carousel
    call mvnw.cmd spring-boot:run
) else (
    echo Usage: start-services.bat [service-name]
    echo.
    echo Available services:
    echo   service-registry  - Eureka Service Registry (Port 8761)
    echo   api-gateway      - API Gateway Service (Port 8080)
    echo   auth             - Authentication Service (Port 8082)
    echo   user             - User Service (Port 8085)
    echo   client           - Client Service (Port 8084)
    echo   categories       - Categories Service (Port 8086)
    echo   carousel         - Carousel Service (Port 8087)
    echo.
    echo Recommended startup order:
    echo 1. start-services.bat service-registry
    echo 2. start-services.bat api-gateway
    echo 3. start-services.bat auth
    echo 4. start-services.bat user
    echo 5. start-services.bat client
    echo 6. start-services.bat categories
    echo 7. start-services.bat carousel
)