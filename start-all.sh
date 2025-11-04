#!/bin/bash

echo "🚀 Starting all microservices..."

# Color codes for better readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directory
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Function to start a service
start_service() {
    local service_name=$1
    local service_dir=$2
    
    echo -e "${BLUE}Starting $service_name...${NC}"
    cd "$BASE_DIR/$service_dir"
    mvn spring-boot:run > "logs/$service_name.log" 2>&1 &
    echo $! > "logs/$service_name.pid"
    echo -e "${GREEN}✓ $service_name started (PID: $(cat logs/$service_name.pid))${NC}"
}

# Create logs directory if it doesn't exist
mkdir -p logs

# Start services in order
echo "================================================"
echo "  Starting Service Registry (Eureka Server)    "
echo "================================================"
start_service "service-registry" "service-registry"
sleep 15  # Wait for Eureka to fully start

echo ""
echo "================================================"
echo "  Starting API Gateway                          "
echo "================================================"
start_service "api-gateway" "api-gateway"
sleep 10

echo ""
echo "================================================"
echo "  Starting Auth Service                         "
echo "================================================"
start_service "auth" "auth"
sleep 10

echo ""
echo "================================================"
echo "  Starting Categories Service                   "
echo "================================================"
start_service "categories" "categories"
sleep 10

echo ""
echo "================================================"
echo "  Starting User Service                         "
echo "================================================"
start_service "user" "user"
sleep 10

echo ""
echo "================================================"
echo "  Starting Client Service                       "
echo "================================================"
start_service "client" "client"
sleep 10

echo ""
echo "================================================"
echo "  Starting Carousel Service                     "
echo "================================================"
start_service "carousel" "carousel"
sleep 10

echo ""
echo "================================================"
echo "  🎉 All services started successfully!         "
echo "================================================"
echo ""
echo "Service URLs:"
echo "  • Eureka Dashboard: http://localhost:8761"
echo "  • API Gateway:      http://localhost:8080"
echo "  • Auth Service:     http://localhost:8081"
echo "  • Categories:       http://localhost:8082"
echo "  • User Service:     http://localhost:8083"
echo "  • Client Service:   http://localhost:8084"
echo "  • Carousel Service: http://localhost:8085"
echo ""
echo "Logs are available in the 'logs' directory"
echo "To stop all services, run: ./stop-all.sh"
