@echo off
REM Start all My-Shop microservices in the correct order
REM This script starts each service in a new command prompt window

echo =================================
echo Starting My-Shop Microservices
echo =================================
echo.

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

echo Environment variables set.
echo.

echo Starting services in order...
echo.

echo [1/7] Starting Service Registry (Port 8761)...
start "Service Registry" cmd /k "cd /d %cd% && start-services.bat service-registry"
timeout /t 10 /nobreak >nul

echo [2/7] Starting API Gateway (Port 8080)...
start "API Gateway" cmd /k "cd /d %cd% && start-services.bat api-gateway"
timeout /t 5 /nobreak >nul

echo [3/7] Starting Auth Service (Port 8082)...
start "Auth Service" cmd /k "cd /d %cd% && start-services.bat auth"
timeout /t 5 /nobreak >nul

echo [4/7] Starting User Service (Port 8085)...
start "User Service" cmd /k "cd /d %cd% && start-services.bat user"
timeout /t 3 /nobreak >nul

echo [5/7] Starting Client Service (Port 8084)...
start "Client Service" cmd /k "cd /d %cd% && start-services.bat client"
timeout /t 3 /nobreak >nul

echo [6/7] Starting Categories Service (Port 8086)...
start "Categories Service" cmd /k "cd /d %cd% && start-services.bat categories"
timeout /t 3 /nobreak >nul

echo [7/7] Starting Carousel Service (Port 8087)...
start "Carousel Service" cmd /k "cd /d %cd% && start-services.bat carousel"

echo.
echo =================================
echo All services are starting up!
echo =================================
echo.
echo Check each service window for startup status.
echo Services will be available at:
echo   Service Registry: http://localhost:8761
echo   API Gateway:      http://localhost:8080
echo   Auth Service:     http://localhost:8082/api/v1/auth
echo   User Service:     http://localhost:8085/api/v1/users
echo   Client Service:   http://localhost:8084/api/v1/client
echo   Categories:       http://localhost:8086/api/v1
echo   Carousel:         http://localhost:8087/api/v1
echo.
echo Wait for all services to start before testing.
echo Press any key to exit this window...
pause >nul