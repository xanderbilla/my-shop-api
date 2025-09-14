#!/bin/bash

# ECR Registry Configuration
ECR_REGISTRY="public.ecr.aws/k2g9v6r8"
PROJECT_NAME="spring-microservice"

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

# Function to start services with proper sequence
start_services() {
    echo "🚀 Starting microservices with proper startup sequence..."
    
    # Start service registry first
    echo "1️⃣ Starting Service Registry (Eureka)..."
    docker-compose up -d service-registry
    
    # Start API Gateway
    echo "2️⃣ Starting API Gateway..."
    docker-compose up -d api-gateway
    
    # Start remaining services
    echo "3️⃣ Starting remaining services..."
    docker-compose up -d auth-service admin-service client-service
    
    echo "✅ All services started!"
}

# Function to start services with simple mode (no healthchecks)
start_services_simple() {
    echo "🚀 Starting microservices in simple mode..."
    docker-compose -f docker-compose-simple.yml up -d
    
    echo "⏳ Waiting for services to initialize..."
    echo "1️⃣ Service Registry starting..."
    sleep 20
    echo "2️⃣ API Gateway starting..."
    sleep 15
    echo "3️⃣ Other services starting..."
    sleep 10
    echo "✅ All services started!"
}

# Function to stop services
stop_services() {
    echo "🛑 Stopping microservices..."
    docker-compose down
    docker-compose -f docker-compose-simple.yml down 2>/dev/null || true
}

# Function to check service status
check_status() {
    echo "📊 Checking service status..."
    docker-compose ps
    echo ""
    echo "🌐 Services URLs:"
    echo "  Service Registry: http://localhost:8761"
    echo "  API Gateway: http://localhost:8080"
    echo "  Auth Service: http://localhost:8082"
    echo "  Admin Service: http://localhost:8083"
    echo "  Client Service: http://localhost:8084"
}

# Function to show logs
show_logs() {
    if [ -z "$1" ]; then
        echo "📋 Showing logs for all services..."
        docker-compose logs -f
    else
        echo "📋 Showing logs for $1..."
        docker-compose logs -f $1
    fi
}

# Function to restart a specific service
restart_service() {
    if [ -z "$1" ]; then
        echo "❌ Please specify a service name"
        echo "Available services: service-registry, api-gateway, auth-service, admin-service, client-service"
        return 1
    fi
    echo "🔄 Restarting $1..."
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
    "start")
        authenticate_ecr
        pull_images
        start_services
        sleep 5
        check_status
        ;;
    "start-simple")
        authenticate_ecr
        pull_images
        start_services_simple
        sleep 5
        check_status
        ;;
    "stop")
        stop_services
        ;;
    "status")
        check_status
        ;;
    "logs")
        show_logs $2
        ;;
    "restart")
        restart_service $2
        ;;
    "update")
        echo "🔄 Updating services..."
        authenticate_ecr
        pull_images
        docker-compose up -d --force-recreate
        sleep 10
        check_status
        ;;
    *)
        echo "🐳 Spring Microservices Docker Management"
        echo ""
        echo "Usage: $0 {auth|pull|start|start-simple|stop|status|logs|restart|update}"
        echo ""
        echo "Commands:"
        echo "  auth         - Authenticate with AWS ECR Public"
        echo "  pull         - Pull latest images from ECR"
        echo "  start        - Start all services with healthchecks (recommended)"
        echo "  start-simple - Start all services without healthchecks (faster)"
        echo "  stop         - Stop all services"
        echo "  status       - Check service status"
        echo "  logs         - Show logs (optional: specify service name)"
        echo "  restart      - Restart a specific service"
        echo "  update       - Pull latest images and recreate containers"
        echo ""
        echo "Examples:"
        echo "  $0 start"
        echo "  $0 start-simple"
        echo "  $0 logs auth-service"
        echo "  $0 restart api-gateway"
        exit 1
        ;;
esac
