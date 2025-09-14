#!/bin/bash

# ECR Registry Configuration
ECR_REGISTRY="public.ecr.aws/k2g9v6r8"
PROJECT_NAME="spring-microservice"

# Service Configuration
SERVICES=("service-registry" "api-gateway" "auth" "admin" "client")
SERVICE_PORTS=(8761 8080 8082 8083 8084)

# Maven PID tracking (using temporary files in /tmp that get cleaned up)
MAVEN_PID_DIR="/tmp/spring-microservice-$$"

# CloudFormation Configuration
CF_TEMPLATE_PATH="./cloudformation/cognito-template.yaml"
DEFAULT_STACK_NAME="spring-microservice-cognito"
DEFAULT_PROJECT_NAME="spring-microservice"
DEFAULT_ENVIRONMENT="dev"

# Cleanup function to remove temporary files
cleanup() {
    rm -rf "$MAVEN_PID_DIR" 2>/dev/null || true
}

# Function to clear Maven log files
clear_logs() {
    echo "🧹 Clearing Maven log files..."
    if [ -d "logs" ]; then
        rm -f logs/*.log
        echo "✅ Log files cleared"
    else
        echo "✅ No log directory found - nothing to clear"
    fi
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
    
    # Set environment variables for auth service
    if [ "$service" = "auth" ]; then
        echo "🔧 Setting Cognito environment variables for auth service..."
        export AWS_COGNITO_REGION=${AWS_COGNITO_REGION:-us-east-1}
        export AWS_COGNITO_USER_POOL_ID=${AWS_COGNITO_USER_POOL_ID:-}
        export AWS_COGNITO_CLIENT_ID=${AWS_COGNITO_CLIENT_ID:-}
        export AWS_COGNITO_CLIENT_SECRET=${AWS_COGNITO_CLIENT_SECRET:-}
    fi
    
    # Create logs directory if it doesn't exist
    mkdir -p logs
    
    # Start Maven with proper logging
    nohup mvn spring-boot:run > "../logs/$service.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$MAVEN_PID_DIR/$service.pid"
    cd ..
    
    echo "✅ $service started with PID $pid"
    echo "📋 Logs: logs/$service.log"
    return 0
}

# Function to start all services with Maven
start_services_maven() {
    echo "🚀 Starting all microservices with Maven..."
    
    # Create logs directory if it doesn't exist
    mkdir -p logs
    
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
    
    # Find service port
    local port=""
    for i in "${!SERVICES[@]}"; do
        if [ "${SERVICES[$i]}" = "$service" ]; then
            port="${SERVICE_PORTS[$i]}"
            break
        fi
    done
    
    # Stop any process using the service port
    if check_port $port; then
        echo "🛑 Stopping service on port $port..."
        local existing_pid=$(lsof -ti :$port)
        if [ -n "$existing_pid" ]; then
            kill -TERM $existing_pid
            sleep 3
            if kill -0 $existing_pid 2>/dev/null; then
                kill -KILL $existing_pid
            fi
            echo "✅ Stopped process with PID: $existing_pid"
        fi
    fi
    
    # Remove PID file if it exists
    local pid_file="$MAVEN_PID_DIR/$service.pid"
    [ -f "$pid_file" ] && rm -f "$pid_file"
    
    # Wait a bit for port to be released
    sleep 2
    
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

# Function to deploy Cognito stack
deploy_cognito() {
    local stack_name="${1:-$DEFAULT_STACK_NAME}"
    local project_name="${2:-$DEFAULT_PROJECT_NAME}"
    local environment="${3:-$DEFAULT_ENVIRONMENT}"
    
    echo "🚀 Deploying Cognito stack..."
    echo "Stack Name: $stack_name"
    echo "Project Name: $project_name"
    echo "Environment: $environment"
    
    if [ ! -f "$CF_TEMPLATE_PATH" ]; then
        echo "❌ CloudFormation template not found at: $CF_TEMPLATE_PATH"
        return 1
    fi
    
    local start_time=$(date +%s)
    
    aws cloudformation deploy \
        --template-file "$CF_TEMPLATE_PATH" \
        --stack-name "$stack_name" \
        --parameter-overrides \
            ProjectName="$project_name" \
            Environment="$environment" \
        --capabilities CAPABILITY_IAM \
        --no-fail-on-empty-changeset
    
    if [ $? -eq 0 ]; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo "✅ Cognito stack deployed successfully!"
        echo "⏱️  Deployment took ${duration} seconds"
        show_cognito_info "$stack_name" "$project_name" "$environment"
    else
        echo "❌ Failed to deploy Cognito stack"
        return 1
    fi
}

# Function to show Cognito information
show_cognito_info() {
    local stack_name="${1:-$DEFAULT_STACK_NAME}"
    local project_name="${2:-$DEFAULT_PROJECT_NAME}"
    local environment="${3:-$DEFAULT_ENVIRONMENT}"
    
    echo "📋 Retrieving Cognito information..."
    
    # Get stack outputs
    local user_pool_id=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`UserPoolId`].OutputValue' \
        --output text 2>/dev/null)
    
    local client_id=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`UserPoolClientId`].OutputValue' \
        --output text 2>/dev/null)
    
    local region=$(aws configure get region 2>/dev/null || echo "us-east-1")
    
    if [ -z "$user_pool_id" ] || [ -z "$client_id" ]; then
        echo "❌ Could not retrieve Cognito information. Stack may not exist or be ready."
        return 1
    fi
    
    # Get client secret
    local client_secret=$(aws cognito-idp describe-user-pool-client \
        --user-pool-id "$user_pool_id" \
        --client-id "$client_id" \
        --query 'UserPoolClient.ClientSecret' \
        --output text 2>/dev/null)
    
    echo ""
    echo "🎯 Cognito Configuration:"
    echo "======================================"
    echo "Stack Name: $stack_name"
    echo "Project: $project_name"
    echo "Environment: $environment"
    echo "Region: $region"
    echo "User Pool ID: $user_pool_id"
    echo "Client ID: $client_id"
    echo "Client Secret: $client_secret"
    echo "======================================"
    echo ""
    echo "🔧 Environment Variables (copy and paste):"
    echo "export AWS_COGNITO_REGION=$region"
    echo "export AWS_COGNITO_USER_POOL_ID=$user_pool_id"
    echo "export AWS_COGNITO_CLIENT_ID=$client_id"
    echo "export AWS_COGNITO_CLIENT_SECRET=$client_secret"
    echo ""
    echo "Or run: ./local-run.sh set-cognito-env $stack_name"
}

# Function to set Cognito environment variables
set_cognito_env() {
    local stack_name="${1:-$DEFAULT_STACK_NAME}"
    
    echo "🔧 Setting Cognito environment variables..."
    
    # Get stack outputs
    local user_pool_id=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`UserPoolId`].OutputValue' \
        --output text 2>/dev/null)
    
    local client_id=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`UserPoolClientId`].OutputValue' \
        --output text 2>/dev/null)
    
    local region=$(aws configure get region 2>/dev/null || echo "us-east-1")
    
    if [ -z "$user_pool_id" ] || [ -z "$client_id" ]; then
        echo "❌ Could not retrieve Cognito information. Stack may not exist or be ready."
        return 1
    fi
    
    # Get client secret
    local client_secret=$(aws cognito-idp describe-user-pool-client \
        --user-pool-id "$user_pool_id" \
        --client-id "$client_id" \
        --query 'UserPoolClient.ClientSecret' \
        --output text 2>/dev/null)
    
    # Export environment variables
    export AWS_COGNITO_REGION="$region"
    export AWS_COGNITO_USER_POOL_ID="$user_pool_id"
    export AWS_COGNITO_CLIENT_ID="$client_id"
    export AWS_COGNITO_CLIENT_SECRET="$client_secret"
    
    echo "✅ Environment variables set!"
    echo "Region: $AWS_COGNITO_REGION"
    echo "User Pool ID: $AWS_COGNITO_USER_POOL_ID"
    echo "Client ID: $AWS_COGNITO_CLIENT_ID"
    echo "Client Secret: [REDACTED]"
    echo ""
    echo "Note: These variables are only set for the current shell session."
    echo "Add them to your ~/.zshrc or ~/.bashrc for persistence."
}

# Function to check Cognito stack status
cognito_status() {
    local stack_name="${1:-$DEFAULT_STACK_NAME}"
    
    echo "📊 Checking Cognito stack status..."
    
    local status=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].StackStatus' \
        --output text 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo "Stack Name: $stack_name"
        echo "Status: $status"
        
        if [ "$status" = "CREATE_COMPLETE" ] || [ "$status" = "UPDATE_COMPLETE" ]; then
            echo "✅ Stack is ready"
            show_cognito_info "$stack_name"
        else
            echo "⏳ Stack is not ready yet"
        fi
    else
        echo "❌ Stack not found or error retrieving status"
        return 1
    fi
}

# Function to start services with proper sequence (Docker)

# Function to deploy Cognito stack
deploy_cognito() {
    local stack_name="${1:-$DEFAULT_STACK_NAME}"
    local project_name="${2:-$DEFAULT_PROJECT_NAME}"
    local environment="${3:-$DEFAULT_ENVIRONMENT}"
    
    echo "🚀 Deploying Cognito stack..."
    echo "Stack Name: $stack_name"
    echo "Project Name: $project_name"
    echo "Environment: $environment"
    
    if [ ! -f "$CF_TEMPLATE_PATH" ]; then
        echo "❌ CloudFormation template not found at: $CF_TEMPLATE_PATH"
        return 1
    fi
    
    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        echo "❌ AWS CLI is not installed. Please install it first."
        return 1
    fi
    
    # Deploy the stack
    echo "📡 Deploying CloudFormation stack..."
    aws cloudformation deploy \
        --template-file "$CF_TEMPLATE_PATH" \
        --stack-name "$stack_name" \
        --parameter-overrides \
            ProjectName="$project_name" \
            Environment="$environment" \
        --capabilities CAPABILITY_IAM \
        --no-fail-on-empty-changeset
    
    if [ $? -eq 0 ]; then
        echo "✅ Cognito stack deployed successfully!"
        echo ""
        show_cognito_info "$stack_name" "$project_name" "$environment"
    else
        echo "❌ Failed to deploy Cognito stack"
        return 1
    fi
}

# Function to show Cognito information
show_cognito_info() {
    local stack_name="${1:-$DEFAULT_STACK_NAME}"
    local project_name="${2:-$DEFAULT_PROJECT_NAME}"
    local environment="${3:-$DEFAULT_ENVIRONMENT}"
    
    echo "📋 Retrieving Cognito information..."
    
    # Get stack outputs
    local user_pool_id=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`UserPoolId`].OutputValue' \
        --output text 2>/dev/null)
    
    local client_id=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`UserPoolClientId`].OutputValue' \
        --output text 2>/dev/null)
    
    local region=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`Region`].OutputValue' \
        --output text 2>/dev/null)
    
    if [ -z "$user_pool_id" ] || [ -z "$client_id" ] || [ -z "$region" ]; then
        echo "❌ Failed to retrieve stack outputs. Stack might not be deployed yet."
        return 1
    fi
    
    # Get client secret
    local client_secret=$(aws cognito-idp describe-user-pool-client \
        --user-pool-id "$user_pool_id" \
        --client-id "$client_id" \
        --query 'UserPoolClient.ClientSecret' \
        --output text 2>/dev/null)
    
    echo ""
    echo "🎯 Cognito Configuration:"
    echo "=========================="
    echo "User Pool ID: $user_pool_id"
    echo "Client ID: $client_id"
    echo "Client Secret: $client_secret"
    echo "Region: $region"
    echo ""
    echo "� Environment Variables:"
    echo "=========================="
    echo "export AWS_COGNITO_REGION=$region"
    echo "export AWS_COGNITO_USER_POOL_ID=$user_pool_id"
    echo "export AWS_COGNITO_CLIENT_ID=$client_id"
    echo "export AWS_COGNITO_CLIENT_SECRET=$client_secret"
    echo ""
    echo "💡 To use these values, run:"
    echo "./local-run.sh set-cognito-env $stack_name"
}

# Function to set Cognito environment variables
set_cognito_env() {
    local stack_name="${1:-$DEFAULT_STACK_NAME}"
    
    echo "🔧 Setting Cognito environment variables..."
    
    # Get stack outputs
    local user_pool_id=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`UserPoolId`].OutputValue' \
        --output text 2>/dev/null)
    
    local client_id=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`UserPoolClientId`].OutputValue' \
        --output text 2>/dev/null)
    
    local region=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`Region`].OutputValue' \
        --output text 2>/dev/null)
    
    if [ -z "$user_pool_id" ] || [ -z "$client_id" ] || [ -z "$region" ]; then
        echo "❌ Failed to retrieve stack outputs. Stack might not be deployed yet."
        return 1
    fi
    
    # Get client secret
    local client_secret=$(aws cognito-idp describe-user-pool-client \
        --user-pool-id "$user_pool_id" \
        --client-id "$client_id" \
        --query 'UserPoolClient.ClientSecret' \
        --output text 2>/dev/null)
    
    # Export environment variables
    export AWS_COGNITO_REGION="$region"
    export AWS_COGNITO_USER_POOL_ID="$user_pool_id"
    export AWS_COGNITO_CLIENT_ID="$client_id"
    export AWS_COGNITO_CLIENT_SECRET="$client_secret"
    
    echo "✅ Environment variables set:"
    echo "AWS_COGNITO_REGION=$AWS_COGNITO_REGION"
    echo "AWS_COGNITO_USER_POOL_ID=$AWS_COGNITO_USER_POOL_ID"
    echo "AWS_COGNITO_CLIENT_ID=$AWS_COGNITO_CLIENT_ID"
    echo "AWS_COGNITO_CLIENT_SECRET=***hidden***"
}

# Function to delete Cognito stack
delete_cognito() {
    local stack_name="${1:-$DEFAULT_STACK_NAME}"
    
    echo "🗑️  Deleting Cognito stack: $stack_name"
    echo "⚠️  This action cannot be undone!"
    
    read -p "Are you sure you want to delete the stack? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🚀 Deleting CloudFormation stack..."
        aws cloudformation delete-stack --stack-name "$stack_name"
        
        if [ $? -eq 0 ]; then
            echo "✅ Stack deletion initiated. Check AWS Console for progress."
        else
            echo "❌ Failed to initiate stack deletion"
            return 1
        fi
    else
        echo "❌ Stack deletion cancelled"
    fi
}

# Function to check Cognito stack status
cognito_status() {
    local stack_name="${1:-$DEFAULT_STACK_NAME}"
    
    echo "📊 Checking Cognito stack status..."
    
    local status=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].StackStatus' \
        --output text 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo "Stack Name: $stack_name"
        echo "Status: $status"
        
        if [ "$status" = "CREATE_COMPLETE" ] || [ "$status" = "UPDATE_COMPLETE" ]; then
            echo "✅ Stack is ready"
            show_cognito_info "$stack_name"
        else
            echo "⏳ Stack is not ready yet"
        fi
    else
        echo "❌ Stack not found or error retrieving status"
        return 1
    fi
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
        if [ -z "$service" ]; then
            echo "📋 Showing Maven logs for all services..."
            echo "Available log files:"
            ls -la logs/*.log 2>/dev/null || echo "No log files found. Make sure services are running."
            echo ""
            echo "To view logs for a specific service, use: $0 logs maven [service-name]"
            echo "Available services: ${SERVICES[*]}"
        else
            local log_file="logs/$service.log"
            if [ -f "$log_file" ]; then
                echo "📋 Showing Maven logs for $service (live tail)..."
                echo "Press Ctrl+C to stop following logs"
                echo "----------------------------------------"
                tail -f "$log_file"
            else
                echo "❌ Log file not found: $log_file"
                echo "Available log files:"
                ls -la logs/*.log 2>/dev/null || echo "No log files found."
                echo ""
                echo "Available services: ${SERVICES[*]}"
                echo "Make sure the service is running with Maven."
            fi
        fi
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

# Function to clear all users from Cognito User Pool
clear_cognito_users() {
    local stack_name="${1:-$DEFAULT_STACK_NAME}"
    
    echo "🧹 Clearing all users from Cognito User Pool..."
    
    # Get User Pool ID from CloudFormation stack
    local user_pool_id=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].Outputs[?OutputKey==`UserPoolId`].OutputValue' \
        --output text 2>/dev/null)
    
    if [ -z "$user_pool_id" ] || [ "$user_pool_id" = "None" ]; then
        echo "❌ Could not retrieve User Pool ID from stack: $stack_name"
        echo "Make sure the Cognito stack is deployed and accessible."
        return 1
    fi
    
    echo "User Pool ID: $user_pool_id"
    
    # Get list of all users
    echo "📋 Fetching list of users..."
    local users=$(aws cognito-idp list-users \
        --user-pool-id "$user_pool_id" \
        --query 'Users[].Username' \
        --output text 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to fetch users from User Pool"
        return 1
    fi
    
    if [ -z "$users" ] || [ "$users" = "None" ]; then
        echo "✅ No users found in User Pool - already clean!"
        return 0
    fi
    
    # Convert users string to array
    local user_array=($users)
    local user_count=${#user_array[@]}
    
    echo "Found $user_count users to delete:"
    for username in "${user_array[@]}"; do
        echo "  - $username"
    done
    
    echo ""
    read -p "Are you sure you want to delete ALL $user_count users? (y/N): " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        echo "🗑️  Deleting users..."
        local deleted=0
        local failed=0
        
        for username in "${user_array[@]}"; do
            echo -n "Deleting user: $username ... "
            if aws cognito-idp admin-delete-user \
                --user-pool-id "$user_pool_id" \
                --username "$username" >/dev/null 2>&1; then
                echo "✅ deleted"
                ((deleted++))
            else
                echo "❌ failed"
                ((failed++))
            fi
        done
        
        echo ""
        echo "📊 Summary:"
        echo "  ✅ Successfully deleted: $deleted users"
        echo "  ❌ Failed to delete: $failed users"
        
        if [ $failed -eq 0 ]; then
            echo "🎉 All users cleared successfully!"
        else
            echo "⚠️  Some users could not be deleted. Check AWS console for details."
        fi
    else
        echo "❌ Operation cancelled by user"
        return 1
    fi
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
    "deploy-cognito")
        shift # Remove the command from arguments
        deploy_cognito "$@"
        ;;
    "cognito-info")
        shift
        show_cognito_info "$@"
        ;;
    "set-cognito-env")
        shift
        set_cognito_env "$@"
        ;;
    "cognito-status")
        shift
        cognito_status "$@"
        ;;
    "clear-users")
        shift
        clear_cognito_users "$@"
        ;;
    "clear-logs")
        clear_logs
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
        echo "  clear-logs        - Clear all Maven log files"
        echo ""
        echo "🔄 Restart Commands:"
        echo "  restart docker [service]    - Restart Docker service"
        echo "  restart maven [service]     - Restart Maven service"
        echo "  restart maven all           - Restart all Maven services"
        echo ""
        echo "☁️ AWS Cognito Commands:"
        echo "  deploy-cognito [stack-name] [project-name] [environment]"
        echo "                        - Deploy Cognito User Pool via CloudFormation"
        echo "  cognito-info [stack-name] - Show Cognito configuration and env vars"
        echo "  set-cognito-env [stack-name] - Set Cognito environment variables"
        echo "  cognito-status [stack-name] - Check Cognito stack status"
        echo "  clear-users [stack-name] - Clear all users from Cognito User Pool"
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
        echo ""
        echo "  # Cognito Examples:"
        echo "  $0 deploy-cognito        # Deploy with default settings"
        echo "  $0 cognito-info          # Show Cognito configuration"
        echo "  $0 set-cognito-env       # Set environment variables"
        echo ""
        echo "📋 Default Cognito Settings:"
        echo "  Stack Name: $DEFAULT_STACK_NAME"
        echo "  Project Name: $DEFAULT_PROJECT_NAME"
        echo "  Environment: $DEFAULT_ENVIRONMENT"
        echo "  Template: $CF_TEMPLATE_PATH"
        exit 1
        ;;
esac
