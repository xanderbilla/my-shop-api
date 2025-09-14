#!/bin/bash

# Spring Microservices Management Script
# Version: 2.0

set -e

# Configuration
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

# Function to compile and validate CloudFormation template
compile_cf_template() {
    log_header "Compiling CloudFormation template..."
    
    if [ ! -f "$CF_TEMPLATE_PATH" ]; then
        log_error "CloudFormation template not found at: $CF_TEMPLATE_PATH"
        return 1
    fi
    
    log_info "Validating CloudFormation template..."
    aws cloudformation validate-template --template-body file://$CF_TEMPLATE_PATH > /dev/null
    
    if [ $? -eq 0 ]; then
        log_success "CloudFormation template is valid"
        return 0
    else
        log_error "CloudFormation template validation failed"
        return 1
    fi
}

# Function to deploy CloudFormation stack
deploy_stack() {
    local stack_name=$1
    local account_id=$(get_account_id)
    local full_stack_name="${stack_name}-${account_id}-auth"
    
    log_header "Deploying CloudFormation stack: $full_stack_name"
    
    # Check if stack already exists
    local existing_stack=$(aws cloudformation describe-stacks \
        --stack-name "$full_stack_name" \
        --query 'Stacks[0].StackName' \
        --output text 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$existing_stack" ]; then
        log_info "Stack '$full_stack_name' already exists, updating..."
    else
        log_info "Creating new stack '$full_stack_name'..."
    fi
    
    # Start deployment
    log_info "Initiating CloudFormation deployment..."
    
    # Create a temporary file to capture deployment output
    local temp_file=$(mktemp)
    
    # Start deployment in background
    (
        aws cloudformation deploy \
            --template-file "$CF_TEMPLATE_PATH" \
            --stack-name "$full_stack_name" \
            --parameter-overrides \
                Environment="dev" \
                ServiceName="$PROJECT_NAME" \
                UserPoolName="${stack_name}-users" \
            --capabilities CAPABILITY_IAM \
            --no-fail-on-empty-changeset > "$temp_file" 2>&1
        echo $? > "${temp_file}.exit_code"
    ) &
    
    local deploy_pid=$!
    
    # Give deployment a moment to start
    sleep 3
    
    # Start monitoring deployment progress with real-time events
    log_info "Starting real-time CloudFormation event monitoring..."
    monitor_stack_events "$full_stack_name" "deployment"
    local monitor_result=$?
    
    # Wait for deployment to complete
    wait $deploy_pid
    local deploy_exit_code=$(cat "${temp_file}.exit_code" 2>/dev/null || echo "1")
    
    # Show deployment output if there were any messages
    if [ -s "$temp_file" ]; then
        echo ""
        log_info "Deployment output:"
        cat "$temp_file"
    fi
    
    # Cleanup temporary files
    rm -f "$temp_file" "${temp_file}.exit_code"
    
    # Check final result
    if [ $deploy_exit_code -eq 0 ] && [ $monitor_result -eq 0 ]; then
        echo ""
        log_success "✅ Stack deployed successfully: $full_stack_name"
        echo $full_stack_name
        return 0
    else
        echo ""
        log_error "❌ Failed to deploy stack"
        return 1
    fi
}

# Function to export environment config
export_env_config() {
    local stack_name=$1
    
    log_header "Exporting environment configuration..."
    
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
        log_error "Failed to retrieve stack outputs"
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
    
    log_success "Environment variables exported"
    log_info "AWS_COGNITO_REGION=$AWS_COGNITO_REGION"
    log_info "AWS_COGNITO_USER_POOL_ID=$AWS_COGNITO_USER_POOL_ID"
    log_info "AWS_COGNITO_CLIENT_ID=$AWS_COGNITO_CLIENT_ID"
    log_info "AWS_COGNITO_CLIENT_SECRET=***hidden***"
    
    return 0
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
    
    log_info "Monitoring CloudFormation events for $operation..."
    echo ""
    
    while true; do
        # Check stack status
        local stack_status=$(aws cloudformation describe-stacks \
            --stack-name "$stack_name" \
            --query 'Stacks[0].StackStatus' \
            --output text 2>/dev/null)
        
        if [ $? -ne 0 ]; then
            # Stack no longer exists (successful deletion) or error
            if [ "$operation" = "deletion" ]; then
                log_success "Stack successfully deleted!"
                break
            else
                log_error "Error monitoring stack or stack not found"
                break
            fi
        fi
        
        # Get recent events
        local events=$(aws cloudformation describe-stack-events \
            --stack-name "$stack_name" \
            --query 'StackEvents[?Timestamp>`2025-09-01T00:00:00.000Z`].[Timestamp,LogicalResourceId,ResourceType,ResourceStatus,ResourceStatusReason]' \
            --output table 2>/dev/null)
        
        if [ $? -eq 0 ]; then
            # Get the latest event timestamp
            local latest_event=$(aws cloudformation describe-stack-events \
                --stack-name "$stack_name" \
                --query 'StackEvents[0].Timestamp' \
                --output text 2>/dev/null)
            
            # Only show new events
            if [ "$latest_event" != "$last_event_time" ]; then
                clear
                echo -e "${PURPLE}🔄 CloudFormation Stack $operation Progress${NC}"
                echo "Stack: $stack_name"
                echo "Status: $stack_status"
                echo ""
                echo "Recent Events:"
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
        
        sleep 5
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
    echo -e "${PURPLE}🚀 Spring Microservices Management Script v2.0${NC}"
    echo ""
    echo "Usage: $0 {command} [options]"
    echo ""
    echo "📋 Available Commands:"
    echo "====================="
    echo ""
    echo -e "${CYAN}run${NC}                    - Full deployment and service startup"
    echo "                         • Compile CloudFormation template"
    echo "                         • Prompt for stack name"
    echo "                         • Deploy with format: STACKNAME-ACCOUNTID-auth"
    echo "                         • Export environment config"
    echo "                         • Check and kill busy ports"
    echo "                         • Clean compile all services"
    echo "                         • Start services in order"
    echo "                         • Test health endpoints"
    echo ""
    echo -e "${CYAN}deploy${NC}                 - Deploy CloudFormation stack only"
    echo "                         • Compile CloudFormation template"
    echo "                         • Prompt for stack name"
    echo "                         • Deploy with format: STACKNAME-ACCOUNTID-auth"
    echo "                         • Export environment config"
    echo ""
    echo -e "${CYAN}delete${NC}                 - Delete stack and cleanup"
    echo "                         • Stop all services"
    echo "                         • Force kill if needed"
    echo "                         • Clear environment variables"
    echo "                         • Delete CloudFormation stack"
    echo ""
    echo -e "${CYAN}restart [service]${NC}      - Restart specific service"
    echo "                         • Clean compile before restart"
    echo "                         • Available services: ${SERVICES[*]}"
    echo ""
    echo -e "${CYAN}stop [service]${NC}         - Stop specific service"
    echo "                         • Available services: ${SERVICES[*]}"
    echo "                         • Use 'stop all' to stop all services"
    echo ""
    echo -e "${CYAN}status${NC}                 - Show service status and URLs"
    echo ""
    echo -e "${CYAN}help${NC}                   - Show this help message"
    echo ""
    echo "📦 Service Information:"
    echo "======================"
    for i in "${!SERVICES[@]}"; do
        echo "  ${SERVICES[$i]}: port ${SERVICE_PORTS[$i]}"
    done
    echo ""
    echo "🌐 Health Check Endpoints:"
    echo "========================="
    echo "  All health checks are accessible via: http://localhost:8080/api/v1/<service>/actuator/health"
    echo "  Exception: Service Registry: http://localhost:8761/actuator/health"
    echo ""
    echo "Examples:"
    echo "========="
    echo "  $0 run                    # Full deployment and startup"
    echo "  $0 deploy                 # Deploy CloudFormation only"
    echo "  $0 restart auth           # Restart auth service"
    echo "  $0 stop client            # Stop client service"
    echo "  $0 stop all               # Stop all services"
    echo "  $0 status                 # Check service status"
    echo "  $0 delete                 # Delete everything"
}

# Main script logic
case "$1" in
    "run")
        log_header "🚀 Starting full deployment and service startup..."
        
        # Compile CloudFormation template
        log_info "📋 Compiling CloudFormation template..."
        compile_cf_template || exit 1
        
        # Ask for stack name
        stack_name=$(prompt_stack_name)
        account_id=$(get_account_id)
        full_stack_name="${stack_name}-${account_id}-auth"
        
        # Deploy stack with enhanced monitoring
        log_info "☁️  Deploying AWS Cognito infrastructure..."
        deployed_stack=$(deploy_stack $stack_name)
        if [ $? -ne 0 ]; then
            log_error "Infrastructure deployment failed. Aborting service startup."
            exit 1
        fi
        
        # Export environment config
        log_info "⚙️  Configuring environment variables..."
        export_env_config $deployed_stack || exit 1
        
        # Check and kill busy ports
        log_info "🔍 Checking for port conflicts..."
        check_and_kill_busy_ports
        
        # Clean compile all services
        log_info "🔨 Building all microservices..."
        clean_compile_services || exit 1
        
        # Start all services in order
        log_info "🎯 Starting all services..."
        start_all_services
        
        # Test health endpoints
        log_info "🏥 Waiting for services to initialize..."
        sleep 10
        log_info "🔍 Testing service health endpoints..."
        test_health_endpoints
        
        echo ""
        log_success "🎉 Full deployment completed successfully!"
        echo ""
        log_info "📊 Current System Status:"
        show_status
        ;;
        
    "deploy")
        log_header "☁️  Deploying CloudFormation Infrastructure..."
        
        # Compile CloudFormation template
        log_info "📋 Compiling CloudFormation template..."
        compile_cf_template || exit 1
        
        # Ask for stack name
        stack_name=$(prompt_stack_name)
        account_id=$(get_account_id)
        
        # Deploy stack with enhanced monitoring
        log_info "🚀 Starting AWS Cognito infrastructure deployment..."
        deployed_stack=$(deploy_stack $stack_name)
        if [ $? -ne 0 ]; then
            log_error "❌ Infrastructure deployment failed"
            exit 1
        fi
        
        # Export environment config
        log_info "⚙️  Configuring environment variables..."
        export_env_config $deployed_stack || exit 1
        
        echo ""
        log_success "🎉 Infrastructure deployment completed successfully!"
        echo ""
        log_info "📊 Stack Information:"
        echo "   Stack Name: $deployed_stack"
        echo "   Region: $(aws configure get region)"
        echo "   Account: $account_id"
        ;;
        
    "delete")
        log_header "Deleting stack and cleaning up..."
        
        # Stop all services
        stop_all_services
        
        # Clear environment variables
        clear_env_vars
        
        # Ask for stack name to delete
        stack_name=$(prompt_stack_name)
        account_id=$(get_account_id)
        full_stack_name="${stack_name}-${account_id}-auth"
        
        # Delete stack
        delete_stack $full_stack_name
        
        log_success "Cleanup completed!"
        ;;
        
    "restart")
        if [ "$2" = "all" ]; then
            stop_all_services
            clean_compile_services
            start_all_services
            log_success "All services restarted!"
        else
            restart_service $2
        fi
        ;;
        
    "stop")
        if [ "$2" = "all" ] || [ -z "$2" ]; then
            stop_all_services
        else
            stop_service $2
        fi
        ;;
        
    "status")
        show_status
        ;;
        
    "help"|"-h"|"--help")
        show_help
        ;;
        
    *)
        log_error "Unknown command: ${1:-<none>}"
        echo ""
        show_help
        exit 1
        ;;
esac