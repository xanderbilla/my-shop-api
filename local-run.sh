#!/bin/bash

# Spring Microservices Management Script
# Version: 2.0

set -e

# Conf# Function to prompt for stack name
prompt_stack_name() {
    local default_stack="spring-microservice-cognito"
    read -p "Enter stack name [$default_stack]: " stack_name
    stack_name=${stack_name:-$default_stack}
    echo $stack_name
}

# Function to show helpon
PROJECT_NAME="spring-microservice"
SERVICES=("service-registry" "api-gateway" "auth" "admin" "client")
SERVICE_PORTS=(8761 8080 8082 8083 8084)
CF_TEMPLATE_PATH="./cloudformation/cognito-infrastructure.yml"
MAVEN_PID_DIR="/tmp/spring-microservice-$$"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_header() {
    echo -e "${PURPLE}🚀 $1${NC}"
}

# Cleanup function
cleanup() {
    rm -rf "$MAVEN_PID_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Function to check if a port is in use
check_port() {
    local port=$1
    if lsof -i :$port > /dev/null 2>&1; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Function to kill process on port
kill_port() {
    local port=$1
    local service_name=${2:-"service"}
    
    if check_port $port; then
        log_warning "Port $port is busy, killing existing process..."
        local pid=$(lsof -ti :$port)
        if [ -n "$pid" ]; then
            kill -TERM $pid 2>/dev/null || true
            sleep 2
            if kill -0 $pid 2>/dev/null; then
                kill -KILL $pid 2>/dev/null || true
            fi
            log_success "Killed process $pid on port $port"
        fi
    fi
}

# Function to get AWS account ID
get_account_id() {
    aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "unknown"
}

# Function to prompt for stack name
prompt_stack_name() {
    local default_stack="spring-microservice-cognito"
    read -p "Enter stack name [$default_stack]: " stack_name
    stack_name=${stack_name:-$default_stack}
    echo $stack_name
}

# Function to check and kill busy ports
check_and_kill_busy_ports() {
    log_header "Checking for busy ports..."
    
    for i in "${!SERVICES[@]}"; do
        local service="${SERVICES[$i]}"
        local port="${SERVICE_PORTS[$i]}"
        kill_port $port $service
    done
}

# Function to compile a single service
compile_service() {
    local service=$1
    
    if [ -z "$service" ]; then
        log_error "Service name not provided"
        return 1
    fi
    
    # Validate service name
            local valid_service=false
    for valid in "${SERVICES[@]}"; do
        if [ "$service" = "$valid" ]; then
            valid_service=true
            break
        fi
    done
    
    if [ "$valid_service" = false ]; then
        log_error "Invalid service name: $service"
        log_info "Valid services: ${SERVICES[*]}"
        return 1
    fi
    
    if [ -d "$service" ]; then
        log_info "🔨 Compiling $service..."
        cd "$service"
        
        # Run Maven clean compile with better output
        if mvn clean compile -q > "../logs/${service}-compile.log" 2>&1; then
            cd ..
            log_success "✅ $service compiled successfully"
            return 0
        else
            cd ..
            log_error "❌ Failed to compile $service"
            log_info "💡 Check logs/${service}-compile.log for details"
            return 1
        fi
    else
        log_error "Service directory $service not found"
        return 1
    fi
}

# Function to clean compile services
clean_compile_services() {
    log_header "Clean compiling all services..."
    
    for service in "${SERVICES[@]}"; do
        if [ -d "$service" ]; then
            log_info "Clean compiling $service..."
            cd $service
            mvn clean compile -q
            cd ..
            log_success "$service compiled successfully"
        else
            log_warning "Service directory $service not found, skipping..."
        fi
    done
}

# Function to start a service
start_service() {
    local service=$1
    local port=$2
    
    log_info "Starting $service on port $port..."
    
    if [ ! -d "$service" ]; then
        log_error "Service directory $service not found"
        return 1
    fi
    
    # Create PID tracking directory
    mkdir -p "$MAVEN_PID_DIR"
    
    # Create logs directory
    mkdir -p logs
    
    cd $service
    
    # Set environment variables for auth service
    if [ "$service" = "auth" ]; then
        log_info "Setting Cognito environment variables for auth service..."
        export AWS_COGNITO_REGION=${AWS_COGNITO_REGION:-us-east-1}
        export AWS_COGNITO_USER_POOL_ID=${AWS_COGNITO_USER_POOL_ID:-}
        export AWS_COGNITO_CLIENT_ID=${AWS_COGNITO_CLIENT_ID:-}
        export AWS_COGNITO_CLIENT_SECRET=${AWS_COGNITO_CLIENT_SECRET:-}
    fi
    
    # Start service
    nohup mvn spring-boot:run > "../logs/$service.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$MAVEN_PID_DIR/$service.pid"
    cd ..
    
    log_success "$service started with PID $pid"
    
    # Wait a bit for service to initialize
    sleep 3
    
    return 0
}

# Function to start all services in order
start_all_services() {
    log_header "Starting all services in order..."
    
    # Start in order: service-registry -> api-gateway -> auth -> admin -> client
    for i in "${!SERVICES[@]}"; do
        local service="${SERVICES[$i]}"
        local port="${SERVICE_PORTS[$i]}"
        
        start_service $service $port
        
        # Wait longer for service-registry and api-gateway
        if [ "$service" = "service-registry" ]; then
            log_info "Waiting for Service Registry to initialize..."
            sleep 15
        elif [ "$service" = "api-gateway" ]; then
            log_info "Waiting for API Gateway to initialize..."
            sleep 10
        else
            sleep 5
        fi
    done
}

# Function to test health endpoints
test_health_endpoints() {
    log_header "Testing health endpoints..."
    
    local gateway_url="http://localhost:8080"
    local max_retries=30
    local retry_interval=5
    
    for service in "${SERVICES[@]}"; do
        log_info "Testing health endpoint for $service..."
        
        local health_url
        if [ "$service" = "service-registry" ]; then
            health_url="http://localhost:8761/actuator/health"
        else
            health_url="$gateway_url/api/v1/$service/actuator/health"
        fi
        
        local retries=0
        while [ $retries -lt $max_retries ]; do
            if curl -f -s "$health_url" > /dev/null 2>&1; then
                log_success "$service health check passed"
                break
            else
                ((retries++))
                if [ $retries -lt $max_retries ]; then
                    log_info "Health check failed for $service, retrying in ${retry_interval}s... ($retries/$max_retries)"
                    sleep $retry_interval
                else
                    log_error "$service health check failed after $max_retries attempts"
                fi
            fi
        done
    done
}

# Function to stop a specific service
stop_service() {
    local service=$1
    
    log_info "Stopping $service..."
    
    # Get port for service
    local port=""
    for i in "${!SERVICES[@]}"; do
        if [ "${SERVICES[$i]}" = "$service" ]; then
            port="${SERVICE_PORTS[$i]}"
            break
        fi
    done
    
    if [ -z "$port" ]; then
        log_error "Unknown service: $service"
        return 1
    fi
    
    # Kill process on port
    kill_port $port $service
    
    # Remove PID file
    local pid_file="$MAVEN_PID_DIR/$service.pid"
    [ -f "$pid_file" ] && rm -f "$pid_file"
    
    log_success "$service stopped"
}

# Function to stop all services
stop_all_services() {
    log_header "Stopping all services..."
    
    # Stop in reverse order
    for (( i=${#SERVICES[@]}-1 ; i>=0 ; i-- )) ; do
        local service="${SERVICES[$i]}"
        stop_service $service
    done
    
    # Cleanup any remaining java processes
    pkill -f "spring-boot:run" 2>/dev/null || true
    
    log_success "All services stopped"
}

# Function to restart a service
restart_service() {
    local service=$1
    
    if [ -z "$service" ]; then
        log_error "Service name required"
        echo "Available services: ${SERVICES[*]}"
        return 1
    fi
    
    # Check if service is valid
    local found=false
    local port=""
    for i in "${!SERVICES[@]}"; do
        if [ "${SERVICES[$i]}" = "$service" ]; then
            found=true
            port="${SERVICE_PORTS[$i]}"
            break
        fi
    done
    
    if [ "$found" = false ]; then
        log_error "Unknown service: $service"
        echo "Available services: ${SERVICES[*]}"
        return 1
    fi
    
    log_header "Restarting $service..."
    
    # Stop the service
    stop_service $service
    
    # Clean compile the service
    if [ -d "$service" ]; then
        log_info "Clean compiling $service..."
        cd $service
        mvn clean compile -q
        cd ..
    fi
    
    # Start the service
    start_service $service $port
    
    log_success "$service restarted successfully"
}

# Function to show status
show_status() {
    log_header "Service Status"
    
    echo ""
    echo "📊 Service Status:"
    echo "=================="
    
    for i in "${!SERVICES[@]}"; do
        local service="${SERVICES[$i]}"
        local port="${SERVICE_PORTS[$i]}"
        
        if check_port $port; then
            echo -e "  ${GREEN}✅ $service${NC} - Running on port $port"
        else
            echo -e "  ${RED}❌ $service${NC} - Not running on port $port"
        fi
    done
    
    echo ""
    echo "🌐 Service URLs:"
    echo "================"
    echo "  Service Registry: http://localhost:8761"
    echo "  API Gateway: http://localhost:8080"
    echo "  Auth Service: http://localhost:8082"
    echo "  Admin Service: http://localhost:8083"
    echo "  Client Service: http://localhost:8084"
    
    echo ""
    echo "📋 Health Endpoints:"
    echo "==================="
    echo "  Service Registry: http://localhost:8761/actuator/health"
    echo "  API Gateway: http://localhost:8080/api/v1/api-gateway/actuator/health"
    echo "  Auth Service: http://localhost:8080/api/v1/auth/actuator/health"
    echo "  Admin Service: http://localhost:8080/api/v1/admin/actuator/health"
    echo "  Client Service: http://localhost:8080/api/v1/client/actuator/health"
}

# Function to clear environment variables
clear_env_vars() {
    log_info "Clearing environment variables..."
    unset AWS_COGNITO_REGION
    unset AWS_COGNITO_USER_POOL_ID
    unset AWS_COGNITO_CLIENT_ID
    unset AWS_COGNITO_CLIENT_SECRET
    log_success "Environment variables cleared"
}

# Function to monitor CloudFormation stack events
monitor_stack_events() {
    local stack_name=$1
    local operation=$2
    local last_event_time=""
    local wait_count=0
    local max_wait_for_stack=60  # Wait up to 5 minutes for stack to appear (5s * 60 = 300s)
    
    log_info "Monitoring CloudFormation events for $operation..."
    
    while true; do
        # Check stack status
        local stack_status=$(aws cloudformation describe-stacks \
            --stack-name "$stack_name" \
            --query 'Stacks[0].StackStatus' \
            --output text 2>/dev/null)
        
        if [ $? -ne 0 ]; then
            # Stack doesn't exist yet or error occurred
            if [ "$operation" = "deletion" ]; then
                log_success "Stack successfully deleted!"
                return 0
            elif [ "$operation" = "deployment" ]; then
                # For deployment, wait for stack to appear
                wait_count=$((wait_count + 1))
                if [ $wait_count -le $max_wait_for_stack ]; then
                    sleep 5
                    continue
                else
                    log_warning "Stack not visible in CloudFormation yet. Deployment may still be in progress."
                    return 0  # Don't fail, just exit monitoring
                fi
            else
                log_error "Error monitoring stack or stack not found"
                return 1
            fi
        fi
        
        # Reset wait counter once stack is found
        if [ $wait_count -gt 0 ]; then
            log_info "Stack found! Monitoring events..."
            wait_count=0
        fi
        
        # Get recent events (simplified query)
        local events=$(aws cloudformation describe-stack-events \
            --stack-name "$stack_name" \
            --max-items 5 \
            --query 'StackEvents[].{Time:Timestamp,Resource:LogicalResourceId,Status:ResourceStatus}' \
            --output table 2>/dev/null)
        
        if [ $? -eq 0 ]; then
            # Get the latest event timestamp
            local latest_event=$(aws cloudformation describe-stack-events \
                --stack-name "$stack_name" \
                --query 'StackEvents[0].Timestamp' \
                --output text 2>/dev/null)
            
            # Only show new events
            if [ "$latest_event" != "$last_event_time" ]; then
                echo ""
                echo "� CloudFormation Status: $stack_status"
                echo "$events"
                last_event_time="$latest_event"
            fi
        fi
        
        # Check if operation is complete
        case "$stack_status" in
            "DELETE_COMPLETE")
                log_success "Stack deletion completed successfully!"
                return 0
                ;;
            "DELETE_FAILED")
                log_error "Stack deletion failed!"
                return 1
                ;;
            "CREATE_COMPLETE"|"UPDATE_COMPLETE")
                if [ "$operation" = "deployment" ]; then
                    log_success "Stack deployment completed successfully!"
                    return 0
                fi
                ;;
            "CREATE_FAILED"|"UPDATE_FAILED"|"ROLLBACK_COMPLETE"|"ROLLBACK_FAILED")
                if [ "$operation" = "deployment" ]; then
                    log_error "Stack deployment failed!"
                    return 1
                fi
                ;;
        esac
        
        sleep 10  # Check every 10 seconds instead of 5
    done
}

# Function to delete stack
delete_stack() {
    local stack_name=$1
    
    log_header "Deleting CloudFormation stack: $stack_name"
    log_warning "This action cannot be undone!"
    
    # First check if stack exists
    local stack_exists=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].StackName' \
        --output text 2>/dev/null)
    
    if [ $? -ne 0 ] || [ -z "$stack_exists" ]; then
        log_warning "Stack '$stack_name' does not exist or is not accessible"
        return 1
    fi
    
    log_info "Found stack: $stack_exists"
    echo
    read -p "Are you sure you want to delete the stack? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Initiating stack deletion..."
        aws cloudformation delete-stack --stack-name "$stack_name"
        
        if [ $? -eq 0 ]; then
            log_success "Stack deletion initiated successfully"
            echo ""
            log_info "Monitoring deletion progress (Press Ctrl+C to stop monitoring)..."
            sleep 3
            
            # Monitor the deletion progress
            monitor_stack_events "$stack_name" "deletion"
            
        else
            log_error "Failed to initiate stack deletion"
            return 1
        fi
    else
        log_info "Stack deletion cancelled"
    fi
}

# Function to show help
show_help() {
    echo -e "${PURPLE}🚀 Spring Microservices CloudFormation Deployment Script${NC}"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "📋 Available Commands:"
    echo "====================="
    echo ""
    echo -e "${CYAN}deploy${NC}                 - Deploy CloudFormation stack"
    echo "                         • Validates CloudFormation template"
    echo "                         • Prompts for stack name"
    echo "                         • Deploys with format: STACKNAME-ACCOUNTID-auth"
    echo "                         • Exports environment variables"
    echo ""
    echo -e "${CYAN}start [service-name]${NC}   - Start specific service or all services"
    echo "                         • start                   - Start all services in order"
    echo "                         • start auth              - Start auth service only"
    echo "                         • Kills busy ports before starting"
    echo ""
    echo -e "${CYAN}stop [service-name]${NC}    - Stop specific service or all services"
    echo "                         • stop                    - Stop all services"
    echo "                         • stop auth               - Stop auth service"
    echo "                         • Kills process on service port"
    echo ""
    echo -e "${CYAN}restart [service-name]${NC} - Restart specific service or all services"
    echo "                         • restart                 - Restart all services"
    echo "                         • restart auth            - Restart auth service only"
    echo "                         • Includes compilation step"
    echo ""
    echo -e "${CYAN}start-service <name>${NC}   - Start specific service (alias for start)"
    echo -e "${CYAN}stop-service <name>${NC}    - Stop specific service (alias for stop)"
    echo -e "${CYAN}restart-service${NC}        - Restart all services (alias for restart)"
    echo ""
    echo -e "${CYAN}status${NC}                 - Show status of all services"
    echo "                         • Shows running/stopped status"
    echo "                         • Lists service URLs and health endpoints"
    echo ""
    echo "Stack Naming Convention:"
    echo "======================="
    echo "  Input stack name: my-shop"
    echo "  AWS Account ID: 123456789012"
    echo "  Final stack name: my-shop-123456789012-auth"
    echo "  User Pool name: my-shop-users"
    echo ""
    echo "Environment Variables Exported:"
    echo "=============================="
    echo "  AWS_COGNITO_REGION"
    echo "  AWS_COGNITO_USER_POOL_ID"
    echo "  AWS_COGNITO_CLIENT_ID"
    echo "  AWS_COGNITO_CLIENT_SECRET"
    echo ""
    echo "  Variables are saved to .env.cognito file"
    echo "  Load them with: source .env.cognito"
    echo ""
    echo "Available Services:"
    echo "=================="
    echo "  service-registry, api-gateway, auth, admin, client"
    echo ""
    echo "Service Startup Order:"
    echo "====================="
    echo "  1. service-registry (Port 8761)"
    echo "  2. api-gateway (Port 8080)"
    echo "  3. auth (Port 8082)"
    echo "  4. admin (Port 8083)"
    echo "  5. client (Port 8084)"
    echo ""
    echo "Examples:"
    echo "========"
    echo "  $0 deploy                     # Deploy CloudFormation stack"
    echo "  $0 start                      # Start all services in order"
    echo "  $0 start auth                 # Start only auth service"
    echo "  $0 stop                       # Stop all services"
    echo "  $0 stop auth                  # Stop auth service"
    echo "  $0 restart                    # Restart all services"
    echo "  $0 restart auth               # Restart only auth service"
    echo "  $0 status                     # Check service status"
}

# Main script logic
case "$1" in
    "deploy")
        log_header "☁️  Deploying CloudFormation Infrastructure..."
        
        # Compile CloudFormation template
        log_info "📋 Validating CloudFormation template..."
        if [ ! -f "$CF_TEMPLATE_PATH" ]; then
            log_error "CloudFormation template not found at: $CF_TEMPLATE_PATH"
            exit 1
        fi
        
        aws cloudformation validate-template --template-body file://$CF_TEMPLATE_PATH > /dev/null
        if [ $? -ne 0 ]; then
            log_error "CloudFormation template validation failed"
            exit 1
        fi
        log_success "CloudFormation template is valid"
        
        # Ask for stack name
        stack_name=$(prompt_stack_name)
        account_id=$(get_account_id)
        full_stack_name="${stack_name}-${account_id}-auth"
        
        log_info "🚀 Deploying stack: $full_stack_name"
        
        # Deploy CloudFormation stack
        aws cloudformation deploy \
            --template-file "$CF_TEMPLATE_PATH" \
            --stack-name "$full_stack_name" \
            --parameter-overrides \
                Environment="dev" \
                ServiceName="$PROJECT_NAME" \
                UserPoolName="${stack_name}-users" \
            --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
            --no-fail-on-empty-changeset
        
        if [ $? -eq 0 ]; then
            log_success "✅ Stack deployed successfully: $full_stack_name"
            
            # Export environment variables
            log_info "⚙️  Exporting environment variables..."
            
            # Get stack outputs
            user_pool_id=$(aws cloudformation describe-stacks \
                --stack-name "$full_stack_name" \
                --query 'Stacks[0].Outputs[?OutputKey==`UserPoolId`].OutputValue' \
                --output text 2>/dev/null)
            
            client_id=$(aws cloudformation describe-stacks \
                --stack-name "$full_stack_name" \
                --query 'Stacks[0].Outputs[?OutputKey==`UserPoolClientId`].OutputValue' \
                --output text 2>/dev/null)
            
            region=$(aws cloudformation describe-stacks \
                --stack-name "$full_stack_name" \
                --query 'Stacks[0].Outputs[?OutputKey==`Region`].OutputValue' \
                --output text 2>/dev/null)
            
            if [ -n "$user_pool_id" ] && [ -n "$client_id" ] && [ -n "$region" ]; then
                # Get client secret
                client_secret=$(aws cognito-idp describe-user-pool-client \
                    --user-pool-id "$user_pool_id" \
                    --client-id "$client_id" \
                    --query 'UserPoolClient.ClientSecret' \
                    --output text 2>/dev/null)
                
                # Create environment variables file
                env_file=".env.cognito"
                cat > "$env_file" << EOF
# AWS Cognito Environment Variables
# Generated on $(date)
# Stack: $full_stack_name

export AWS_COGNITO_REGION="$region"
export AWS_COGNITO_USER_POOL_ID="$user_pool_id"
export AWS_COGNITO_CLIENT_ID="$client_id"
export AWS_COGNITO_CLIENT_SECRET="$client_secret"
EOF
                
                # Also export to current session
                export AWS_COGNITO_REGION="$region"
                export AWS_COGNITO_USER_POOL_ID="$user_pool_id"
                export AWS_COGNITO_CLIENT_ID="$client_id"
                export AWS_COGNITO_CLIENT_SECRET="$client_secret"
                
                log_success "Environment variables exported successfully!"
                echo ""
                log_info "📊 Stack Information:"
                echo "   Stack Name: $full_stack_name"
                echo "   Region: $region"
                echo "   Account: $account_id"
                echo "   User Pool ID: $user_pool_id"
                echo "   Client ID: $client_id"
                echo "   Client Secret: ***hidden***"
                echo ""
                log_info "💡 Environment variables saved to: $env_file"
                log_info "   To load in new shell sessions, run: source $env_file"
                echo ""
                log_warning "⚠️  Keep the $env_file file secure as it contains sensitive credentials!"
            else
                log_error "Failed to retrieve stack outputs"
                exit 1
            fi
        else
            log_error "❌ Stack deployment failed"
            exit 1
        fi
        ;;
        
    "start-service")
        if [ -z "$2" ]; then
            log_error "Service name required"
            echo "Available services: ${SERVICES[*]}"
            exit 1
        fi
        
        # Validate service name
        service_found=false
        service_port=""
        for i in "${!SERVICES[@]}"; do
            if [ "${SERVICES[$i]}" = "$2" ]; then
                service_found=true
                service_port="${SERVICE_PORTS[$i]}"
                break
            fi
        done
        
        if [ "$service_found" = false ]; then
            log_error "Unknown service: $2"
            echo "Available services: ${SERVICES[*]}"
            exit 1
        fi
        
        log_header "Starting $2..."
        
        # Kill port if busy
        kill_port $service_port $2
        
        # Start the service
        start_service $2 $service_port
        ;;
        
    "stop-service"|"stop")
        if [ -z "$2" ]; then
            # Stop all services when no service name provided
            stop_all_services
            exit 0
        fi
        
        # Validate service name
        service_found=false
        for service in "${SERVICES[@]}"; do
            if [ "$service" = "$2" ]; then
                service_found=true
                break
            fi
        done
        
        if [ "$service_found" = false ]; then
            log_error "Unknown service: $2"
            echo "Available services: ${SERVICES[*]}"
            exit 1
        fi
        
        stop_service $2
        ;;
        
    "restart"|"start")
        if [ "$1" = "start" ] && [ -z "$2" ]; then
            # Start all services in order
            log_header "Starting all services in order..."
            
            # Source environment variables if available
            if [ -f ".env.cognito" ]; then
                log_info "Loading Cognito environment variables..."
                source .env.cognito
                log_success "Environment variables loaded"
            else
                log_warning "No .env.cognito file found. Run './local-run.sh deploy' first to set up AWS Cognito."
            fi
            
            start_all_services
            
        elif [ "$1" = "restart" ] && [ -z "$2" ]; then
            # Restart all services
            log_header "Restarting all services..."
            
            # Stop all services first
            stop_all_services
            
            # Source environment variables if available
            if [ -f ".env.cognito" ]; then
                log_info "Loading Cognito environment variables..."
                source .env.cognito
                log_success "Environment variables loaded"
            else
                log_warning "No .env.cognito file found. Run './local-run.sh deploy' first to set up AWS Cognito."
            fi
            
            # Clean compile all services
            clean_compile_services
            
            # Start all services
            start_all_services
            
        else
            # Single service restart/start
            if [ -z "$2" ]; then
                log_error "Service name required"
                echo "Available services: ${SERVICES[*]}"
                exit 1
            fi
            
            # Validate service name
            service_found=false
            service_port=""
            for i in "${!SERVICES[@]}"; do
                if [ "${SERVICES[$i]}" = "$2" ]; then
                    service_found=true
                    service_port="${SERVICE_PORTS[$i]}"
                    break
                fi
            done
            
            if [ "$service_found" = false ]; then
                log_error "Unknown service: $2"
                echo "Available services: ${SERVICES[*]}"
                exit 1
            fi
            
            if [ "$1" = "restart" ]; then
                restart_service $2
            else
                # Start single service
                log_header "Starting $2..."
                
                # Kill port if busy
                kill_port $service_port $2
                
                # Source environment variables if available and service is auth
                if [ "$2" = "auth" ] && [ -f ".env.cognito" ]; then
                    log_info "Loading Cognito environment variables for auth service..."
                    source .env.cognito
                fi
                
                # Start the service
                start_service $2 $service_port
            fi
        fi
        ;;
        
    "restart-service")
        log_header "Restarting all services..."
        
        # Stop all services first
        stop_all_services
        
        # Source environment variables if available
        if [ -f ".env.cognito" ]; then
            log_info "Loading Cognito environment variables..."
            source .env.cognito
            log_success "Environment variables loaded"
        else
            log_warning "No .env.cognito file found. Run './local-run.sh deploy' first to set up AWS Cognito."
        fi
        
        # Clean compile all services
        clean_compile_services
        
        # Start all services
        start_all_services
        ;;
        
    "status")
        show_status
        ;;
        
    "help"|"-h"|"--help"|"")
        show_help
        ;;
        
    *)
        log_error "Unknown command: ${1:-<none>}"
        echo ""
        echo "Available commands: deploy, start, stop, restart, start-service, stop-service, restart-service, status"
        echo ""
        show_help
        exit 1
        ;;
esac