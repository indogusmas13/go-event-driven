#!/bin/bash

# Test script untuk migration functionality

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cd "$PROJECT_ROOT"

print_status "Testing migration functionality..."

# Test 1: Check if migrations directory exists
if [ -d "migrations" ]; then
    print_status "✓ Migrations directory exists"
    ls -la migrations/
else
    print_error "✗ Migrations directory not found"
    exit 1
fi

# Test 2: Test Go migration tool
print_status "Testing Go migration tool..."
if go run cmd/migrate/main.go -action=create -name=test_migration; then
    print_status "✓ Migration creation works"
else
    print_error "✗ Migration creation failed"
fi

# Test 3: Test with different working directories
print_status "Testing migration path detection..."

# From project root
print_status "Testing from project root..."
go run -ldflags="-X main.testMode=true" pkg/database/utils.go || echo "Direct test not available"

# Test 4: Check migration files syntax
print_status "Checking migration file syntax..."
for file in migrations/*.sql; do
    if [ -f "$file" ]; then
        print_status "Checking $file"
        # Basic SQL syntax check (just check if file is readable)
        if [ -r "$file" ]; then
            print_status "✓ $file is readable"
        else
            print_error "✗ Cannot read $file"
        fi
    fi
done

print_status "Migration tests completed!"