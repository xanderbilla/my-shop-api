#!/bin/bash

# Simple Multi-platform Build and ECR Push Script
set -e

# Configuration
ECR_REGISTRY="public.ecr.aws/k2g9v6r8"
AWS_REGION="us-east-1"
PLATFORMS="linux/amd64,linux/arm64"

# Services and their exact ECR repository names (from your ECR output)
SERVICES="service-registry:spring-microservice/shop-service-registry api-gateway:spring-microservice/shop-api-gateway auth:spring-microservice/shop-auth client:spring-microservice/shop-client"

docker context use default

echo "🔑 Authenticating with ECR..."
aws ecr-public get-login-password --region ${AWS_REGION} | \
    docker login --username AWS --password-stdin public.ecr.aws

echo "🔧 Setting up Docker buildx for multi-platform builds..."
# Use the default builder which already supports multi-platform
docker buildx use default
echo "Using default builder with multi-platform support"

echo "🚀 Building and pushing multi-platform images..."

for service_pair in $SERVICES; do
    service_dir=$(echo "$service_pair" | cut -d':' -f1)
    ecr_repo=$(echo "$service_pair" | cut -d':' -f2)
    image_name="${ECR_REGISTRY}/${ecr_repo}:latest"
    
    echo ""
    echo "📦 Building ${service_dir} -> ${image_name}"
    echo "   Platforms: ${PLATFORMS}"
    
    cd "${service_dir}"
    
    # Build and push for multiple platforms
    docker buildx build \
        --platform "${PLATFORMS}" \
        --tag "${image_name}" \
        --push \
        .
    
    echo "✅ Successfully pushed ${service_dir}"
    cd ..
done

echo ""
echo "🎉 All services built and pushed successfully!"
echo ""
echo "📋 Built Images:"
for service_pair in $SERVICES; do
    service_dir=$(echo "$service_pair" | cut -d':' -f1)
    ecr_repo=$(echo "$service_pair" | cut -d':' -f2)
    echo "   ${ECR_REGISTRY}/${ecr_repo}:latest"
done

echo ""
echo "🧹 Cleaning up build cache..."
docker buildx prune -f
