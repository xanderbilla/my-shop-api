#!/bin/bash

# ECR Registry Configuration
ECR_REGISTRY="public.ecr.aws/k2g9v6r8"
PROJECT_NAME="spring-microservice"

# Service Configuration
SERVICES=("service-registry" "api-gateway" "auth" "admin" "client")
SERVICE_PORTS=(8761 8080 8082 8083 8084)

# Maven PID tracking (using temporary files in /tmp that get cleaned up)
MAVEN_PID_DIR="/tmp/spring-microservice-$$"

# Cleanup function to remove temporary files
cleanup() {
    rm -rf "$MAVEN_PID_DIR" 2>/dev/null || true
}

# Set trap to cleanup on script exit
trap cleanup EXIT

# Function to authenticate with ECR Public
authenticate_ecr() {
    echo "🔐 Authenticating with AWS ECR Public..."
    aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws
}

# Function to pull latest images
pull_images() {
    echo "📥 Pulling latest images from ECR..."
    docker pull ${ECR_REGISTRY}/${PROJECT_NAME}/shop-service-registry:latest
    docker pull ${ECR_REGISTRY}/${PROJECT_NAME}/shop-api-gateway:latest
    docker pull ${ECR_REGISTRY}/${PROJECT_NAME}/shop-auth:latest
    docker pull ${ECR_REGISTRY}/${PROJECT_NAME}/shop-admin:latest
    docker pull ${ECR_REGISTRY}/${PROJECT_NAME}/shop-client:latest
}

# Function to check if a port is in use
check_port() {
    local port=$1
    if lsof -i :$port > /dev/null 2>&1; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Function to start Maven service in background
start_maven_service() {
    local service=$1
    local port=$2
    
    echo "🚀 Starting $service on port $port using Maven..."
    
    # Check if port is already in use
    if check_port $port; then
        echo "⚠️  Port $port is already in use. Service $service might already be running."
        return 1
    fi
    
    # Create PID tracking directory if it doesn't exist
    mkdir -p "$MAVEN_PID_DIR"
    
    # Change to service directory and start Maven
    cd $service
    nohup mvn spring-boot:run > /dev/null 2>&1 &
    local pid=$!
    echo "$pid" > "$MAVEN_PID_DIR/$service.pid"
    cd ..
    
    echo "✅ $service started with PID $pid"
    return 0
}

# Function to start all services with Maven
start_services_maven() {
    echo "🚀 Starting all microservices with Maven..."
    
    # Clear previous PID tracking
    rm -rf "$MAVEN_PID_DIR"
    mkdir -p "$MAVEN_PID_DIR"
    
    # Start services in proper order
    for i in "${!SERVICES[@]}"; do
        local service="${SERVICES[$i]}"
        local port="${SERVICE_PORTS[$i]}"
        
        start_maven_service $service $port
        
        # Wait a bit between services to avoid startup conflicts
        if [ $i -lt $((${#SERVICES[@]} - 1)) ]; then
            echo "⏳ Waiting 15 seconds before starting next service..."
            sleep 15
        fi
    done
    
    echo "✅ All Maven services started!"
}

# Function to stop Maven services
stop_maven_services() {
    echo "🛑 Stopping Maven services..."
    
    if [ ! -d "$MAVEN_PID_DIR" ]; then
        echo "No Maven services tracked."
        # Try to kill any Spring Boot processes as fallback
        echo "🧹 Checking for any running Spring Boot processes..."
        pkill -f "spring-boot:run" 2>/dev/null && echo "✅ Stopped Spring Boot processes" || echo "No Spring Boot processes found"
        return 0
    fi
    
    for service in "${SERVICES[@]}"; do
        local pid_file="$MAVEN_PID_DIR/$service.pid"
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                echo "🛑 Stopping $service (PID: $pid)..."
                kill -TERM "$pid"
                
                # Wait for graceful shutdown
                sleep 5
                
                # Force kill if still running
                if kill -0 "$pid" 2>/dev/null; then
                    echo "⚡ Force killing $service (PID: $pid)..."
                    kill -KILL "$pid"
                fi
            else
                echo "⚠️  $service (PID: $pid) is not running"
            fi
        fi
    done
    
    # Clean up PID directory
    rm -rf "$MAVEN_PID_DIR"
    echo "✅ All Maven services stopped!"
}

# Function to restart Maven service
restart_maven_service() {
    local service=$1
    
    if [ -z "$service" ]; then
        echo "❌ Please specify a service name"
        echo "Available services: ${SERVICES[*]}"
        return 1
    fi
    
    # Check if service exists
    if [[ ! " ${SERVICES[*]} " =~ " $service " ]]; then
        echo "❌ Invalid service name: $service"
        echo "Available services: ${SERVICES[*]}"
        return 1
    fi
    
    echo "🔄 Restarting $service with Maven..."
    
    # Stop the specific service if it's tracked
    local pid_file="$MAVEN_PID_DIR/$service.pid"
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "🛑 Stopping $service (PID: $pid)..."
            kill -TERM "$pid"
            sleep 5
            if kill -0 "$pid" 2>/dev/null; then
                kill -KILL "$pid"
            fi
        fi
        rm -f "$pid_file"
    fi
    
    # Find service port
    local port=""
    for i in "${!SERVICES[@]}"; do
        if [ "${SERVICES[$i]}" = "$service" ]; then
            port="${SERVICE_PORTS[$i]}"
            break
        fi
    done
    
    # Restart the service
    start_maven_service $service $port
}

# Function to restart all Maven services
restart_all_maven_services() {
    echo "🔄 Restarting all Maven services..."
    stop_maven_services
    sleep 5
    start_services_maven
}

# Function to start services with proper sequence (Docker)
start_services_docker() {
    echo "🚀 Starting microservices with Docker and proper startup sequence..."
    
    # Start service registry first
    echo "1️⃣ Starting Service Registry (Eureka)..."
    docker-compose up -d service-registry
    
    # Start API Gateway
    echo "2️⃣ Starting API Gateway..."
    docker-compose up -d api-gateway
    
    # Start remaining services
    echo "3️⃣ Starting remaining services..."
    docker-compose up -d auth-service admin-service client-service
    
    echo "✅ All Docker services started!"
}

# Function to start services with simple mode (no healthchecks) - Docker
start_services_docker_simple() {
    echo "🚀 Starting microservices in Docker simple mode..."
    docker-compose -f docker-compose-simple.yml up -d
    
    echo "⏳ Waiting for services to initialize..."
    echo "1️⃣ Service Registry starting..."
    sleep 20
    echo "2️⃣ API Gateway starting..."
    sleep 15
    echo "3️⃣ Other services starting..."
    sleep 10
    echo "✅ All Docker services started!"
}

# Function to stop Docker services
stop_docker_services() {
    echo "🛑 Stopping Docker services..."
    docker-compose down
    docker-compose -f docker-compose-simple.yml down 2>/dev/null || true
}

# Function to stop all services (both Docker and Maven)
stop_all_services() {
    echo "🛑 Stopping all services..."
    
    # Stop Docker services
    stop_docker_services
    
    # Stop Maven services
    stop_maven_services
    
    # Also kill any java processes that might be Spring Boot apps
    echo "🧹 Cleaning up any remaining Java processes..."
    pkill -f "spring-boot:run" 2>/dev/null || true
    
    echo "✅ All services stopped!"
}

# Function to check service status
check_status() {
    echo "📊 Checking service status..."
    
    echo "🐳 Docker Services:"
    docker-compose ps
    
    echo ""
    echo "☕ Maven Services:"
    if [ -d "$MAVEN_PID_DIR" ] && [ "$(ls -A $MAVEN_PID_DIR 2>/dev/null)" ]; then
        echo "Running Maven services:"
        for service in "${SERVICES[@]}"; do
            local pid_file="$MAVEN_PID_DIR/$service.pid"
            if [ -f "$pid_file" ]; then
                local pid=$(cat "$pid_file")
                if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                    echo "  ✅ $service (PID: $pid)"
                else
                    echo "  ❌ $service (PID: $pid) - Not running"
                fi
            fi
        done
    else
        echo "  No Maven services tracked (check with 'ps aux | grep spring-boot')"
    fi
    
    echo ""
    echo "🌐 Services URLs:"
    echo "  Service Registry: http://localhost:8761"
    echo "  API Gateway: http://localhost:8080"
    echo "  Auth Service: http://localhost:8082"
    echo "  Admin Service: http://localhost:8083"
    echo "  Client Service: http://localhost:8084"
    
    echo ""
    echo "🔍 Port Status:"
    for i in "${!SERVICES[@]}"; do
        local service="${SERVICES[$i]}"
        local port="${SERVICE_PORTS[$i]}"
        if check_port $port; then
            echo "  ✅ Port $port ($service) - In Use"
        else
            echo "  ❌ Port $port ($service) - Free"
        fi
    done
}

# Function to show logs
show_logs() {
    local service=$1
    local mode=$2
    
    if [ "$mode" = "maven" ]; then
        echo "📋 Maven logs are not stored to files to avoid creating additional files."
        echo "💡 To see Maven logs, you can:"
        echo "   1. Check the terminal where you started the services"
        echo "   2. Use 'ps aux | grep spring-boot' to see running processes"
        echo "   3. Use system logs: 'sudo dmesg | grep java'"
        echo "   4. Or restart services without background mode for live logs"
    else
        # Docker logs
        if [ -z "$service" ]; then
            echo "📋 Showing Docker logs for all services..."
            docker-compose logs -f
        else
            echo "📋 Showing Docker logs for $service..."
            docker-compose logs -f $service
        fi
    fi
}

# Function to restart a specific Docker service
restart_docker_service() {
    if [ -z "$1" ]; then
        echo "❌ Please specify a service name"
        echo "Available services: service-registry, api-gateway, auth-service, admin-service, client-service"
        return 1
    fi
    echo "🔄 Restarting Docker service $1..."
    docker-compose restart $1
}

# Main script logic
case "$1" in
    "auth")
        authenticate_ecr
        ;;
    "pull")
        authenticate_ecr
        pull_images
        ;;
    "start-docker")
        authenticate_ecr
        pull_images
        start_services_docker
        sleep 5
        check_status
        ;;
    "start-docker-simple")
        authenticate_ecr
        pull_images
        start_services_docker_simple
        sleep 5
        check_status
        ;;
    "start-maven")
        start_services_maven
        sleep 5
        check_status
        ;;
    "stop")
        stop_all_services
        ;;
    "stop-docker")
        stop_docker_services
        ;;
    "stop-maven")
        stop_maven_services
        ;;
    "status")
        check_status
        ;;
    "logs")
        if [ "$2" = "maven" ]; then
            show_logs $3 maven
        else
            show_logs $2 docker
        fi
        ;;
    "restart")
        if [ "$2" = "maven" ]; then
            if [ "$3" = "all" ]; then
                restart_all_maven_services
            else
                restart_maven_service $3
            fi
        elif [ "$2" = "docker" ]; then
            restart_docker_service $3
        else
            echo "❌ Please specify mode: maven or docker"
            echo "Usage: $0 restart {maven|docker} [service-name|all]"
        fi
        ;;
    "update")
        echo "🔄 Updating Docker services..."
        authenticate_ecr
        pull_images
        docker-compose up -d --force-recreate
        sleep 10
        check_status
        ;;
    *)
        echo "� Spring Microservices Management Script"
        echo ""
        echo "This script supports both Docker and Maven (non-Docker) execution modes."
        echo ""
        echo "Usage: $0 {command} [options]"
        echo ""
        echo "🐳 Docker Commands:"
        echo "  auth              - Authenticate with AWS ECR Public"
        echo "  pull              - Pull latest images from ECR"
        echo "  start-docker      - Start all services with Docker (with healthchecks)"
        echo "  start-docker-simple - Start all services with Docker (no healthchecks)"
        echo "  stop-docker       - Stop Docker services only"
        echo "  update            - Pull latest images and recreate Docker containers"
        echo ""
        echo "☕ Maven Commands:"
        echo "  start-maven       - Start all services with Maven (non-Docker)"
        echo "  stop-maven        - Stop Maven services only"
        echo ""
        echo "🔧 General Commands:"
        echo "  stop              - Stop ALL services (Docker + Maven)"
        echo "  status            - Check status of all services"
        echo "  logs [service]    - Show Docker logs (optional: specify service)"
        echo "  logs maven [service] - Show Maven logs (optional: specify service)"
        echo ""
        echo "🔄 Restart Commands:"
        echo "  restart docker [service]    - Restart Docker service"
        echo "  restart maven [service]     - Restart Maven service"
        echo "  restart maven all           - Restart all Maven services"
        echo ""
        echo "Available services: ${SERVICES[*]}"
        echo ""
        echo "📡 Service Ports:"
        for i in "${!SERVICES[@]}"; do
            echo "  ${SERVICES[$i]}: ${SERVICE_PORTS[$i]}"
        done
        echo ""
        echo "Examples:"
        echo "  $0 start-docker          # Start with Docker"
        echo "  $0 start-maven           # Start with Maven (no Docker)"
        echo "  $0 restart maven auth    # Restart auth service (Maven)"
        echo "  $0 restart maven all     # Restart all Maven services"
        echo "  $0 logs maven auth       # Show Maven logs for auth service"
        echo "  $0 stop                  # Stop everything"
        exit 1
        ;;
esac
