#!/bin/bash

# Database migration script for go-event-driven project

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MIGRATION_PATH="$PROJECT_ROOT/migrations"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if required tools are installed
check_requirements() {
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed"
        exit 1
    fi
    
    # Check if migrate tool is available
    if ! command -v migrate &> /dev/null; then
        print_warning "golang-migrate CLI not found. Trying to install..."
        go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
        
        if ! command -v migrate &> /dev/null; then
            print_error "Failed to install golang-migrate. Please install manually:"
            echo "go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"
            exit 1
        fi
        print_status "golang-migrate installed successfully"
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  up                 Run all pending migrations"
    echo "  down [N]           Rollback N migrations (default: 1)"
    echo "  create [NAME]      Create new migration files"
    echo "  status             Show current migration status"
    echo "  version            Show current migration version"
    echo "  force [VERSION]    Set migration version without running migrations"
    echo ""
    echo "Environment Variables:"
    echo "  DB_HOST            Database host (default: localhost)"
    echo "  DB_PORT            Database port (default: 5432)"
    echo "  DB_NAME            Database name (default: event_driven_db)"
    echo "  DB_USER            Database user (default: postgres)"
    echo "  DB_PASSWORD        Database password (default: postgres123)"
    echo "  ENV                Environment (development, production, docker)"
    echo ""
    echo "Examples:"
    echo "  $0 up                           # Run all pending migrations"
    echo "  $0 down 2                       # Rollback 2 migrations"
    echo "  $0 create add_user_table        # Create new migration"
    echo "  $0 status                       # Show migration status"
}

# Function to build database URL
build_db_url() {
    local host="${DB_HOST:-localhost}"
    local port="${DB_PORT:-5432}"
    local name="${DB_NAME:-event_driven_db}"
    local user="${DB_USER:-postgres}"
    local password="${DB_PASSWORD:-postgres123}"
    local sslmode="${DB_SSLMODE:-disable}"
    
    echo "postgres://${user}:${password}@${host}:${port}/${name}?sslmode=${sslmode}"
}

# Function to wait for database
wait_for_db() {
    local host="${DB_HOST:-localhost}"
    local port="${DB_PORT:-5432}"
    local max_attempts=30
    local attempt=1
    
    print_status "Waiting for database to be ready..."
    
    while ! nc -z "$host" "$port" 2>/dev/null; do
        if [ $attempt -eq $max_attempts ]; then
            print_error "Database is not ready after $max_attempts attempts"
            exit 1
        fi
        
        print_status "Attempt $attempt/$max_attempts: Database not ready, waiting..."
        sleep 2
        ((attempt++))
    done
    
    print_status "Database is ready!"
}

# Main script logic
main() {
    cd "$PROJECT_ROOT"
    
    case "$1" in
        "up")
            check_requirements
            wait_for_db
            print_status "Running migrations..."
            migrate -path "$MIGRATION_PATH" -database "$(build_db_url)" up
            print_status "Migrations completed!"
            ;;
            
        "down")
            check_requirements
            wait_for_db
            local steps="${2:-1}"
            print_warning "Rolling back $steps migration(s)..."
            migrate -path "$MIGRATION_PATH" -database "$(build_db_url)" down "$steps"
            print_status "Rollback completed!"
            ;;
            
        "create")
            check_requirements
            if [ -z "$2" ]; then
                print_error "Migration name is required"
                echo "Usage: $0 create <migration_name>"
                exit 1
            fi
            
            print_status "Creating migration: $2"
            migrate create -ext sql -dir "$MIGRATION_PATH" -seq "$2"
            print_status "Migration files created in $MIGRATION_PATH"
            ;;
            
        "status"|"version")
            check_requirements
            wait_for_db
            migrate -path "$MIGRATION_PATH" -database "$(build_db_url)" version
            ;;
            
        "force")
            check_requirements
            wait_for_db
            if [ -z "$2" ]; then
                print_error "Version number is required"
                echo "Usage: $0 force <version>"
                exit 1
            fi
            
            print_warning "Forcing migration version to: $2"
            migrate -path "$MIGRATION_PATH" -database "$(build_db_url)" force "$2"
            print_status "Migration version set to $2"
            ;;
            
        "help"|"-h"|"--help"|"")
            show_usage
            ;;
            
        *)
            print_error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"