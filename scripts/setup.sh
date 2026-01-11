#!/bin/bash

# Setup script untuk go-event-driven project

set -e

echo "🚀 Setting up Go Event-Driven Microservices..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if Go is installed (optional, untuk development)
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | cut -d' ' -f3)
    echo "✅ Go version: $GO_VERSION"
else
    echo "⚠️  Go is not installed. Docker containers will be used."
fi

echo "📦 Building and starting services..."

# Build and start all services
docker-compose up --build -d

echo "⏳ Waiting for services to be ready..."

# Wait for PostgreSQL
echo "🔍 Waiting for PostgreSQL..."
until docker-compose exec -T postgres pg_isready -U postgres; do
  sleep 2
done
echo "✅ PostgreSQL is ready"

# Wait for Kafka
echo "🔍 Waiting for Kafka..."
sleep 10
echo "✅ Kafka should be ready"

# Wait for User Service
echo "🔍 Waiting for User Service..."
until curl -s http://localhost:8081/health > /dev/null; do
  sleep 2
done
echo "✅ User Service is ready"

# Wait for BFF
echo "🔍 Waiting for BFF..."
until curl -s http://localhost:8080/health > /dev/null; do
  sleep 2
done
echo "✅ BFF is ready"

echo ""
echo "🎉 All services are up and running!"
echo ""
echo "📋 Service URLs:"
echo "   - BFF Service: http://localhost:8080"
echo "   - User Service: http://localhost:8081"
echo "   - PostgreSQL: localhost:5432"
echo "   - Kafka: localhost:9092"
echo ""
echo "📖 API Documentation:"
echo "   - Health Check BFF: curl http://localhost:8080/health"
echo "   - Health Check User Service: curl http://localhost:8081/health"
echo ""
echo "🔧 To view logs:"
echo "   - All services: docker-compose logs -f"
echo "   - Specific service: docker-compose logs -f [bff|user-service|postgres|kafka]"
echo ""
echo "🛑 To stop services:"
echo "   - docker-compose down"