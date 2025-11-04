#!/bin/bash

echo "🛑 Stopping all microservices..."

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Base directory
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Function to stop a service
stop_service() {
    local service_name=$1
    
    if [ -f "logs/$service_name.pid" ]; then
        local pid=$(cat "logs/$service_name.pid")
        if ps -p $pid > /dev/null 2>&1; then
            echo -e "${RED}Stopping $service_name (PID: $pid)...${NC}"
            kill $pid
            rm "logs/$service_name.pid"
            echo -e "${GREEN}✓ $service_name stopped${NC}"
        else
            echo -e "${RED}$service_name is not running${NC}"
            rm "logs/$service_name.pid"
        fi
    else
        echo -e "${RED}No PID file found for $service_name${NC}"
    fi
}

cd "$BASE_DIR"

# Stop services in reverse order
stop_service "carousel"
stop_service "client"
stop_service "user"
stop_service "categories"
stop_service "auth"
stop_service "api-gateway"
stop_service "service-registry"

echo ""
echo "================================================"
echo "  🛑 All services stopped                       "
echo "================================================"
