# Go Event-Driven Microservices

A distributed microservice system based on HTTP API with an event-driven approach using Go 1.24.

## Architecture

```
┌──────────────┐
│   Frontend   │
└──────┬───────┘
       │ HTTP
       ▼
┌──────────────────────┐
│    BFF (8080)        │  ← Authentication, Rate Limiting
└──────┬───────────────┘
       │ HTTP (Internal)
       ▼
┌──────────────────────┐
│  User Service (8081) │  ← User Management, Password Hashing
└──────┬───────────────┘
       │ Kafka Event
       ▼
┌──────────────────────┐
│  Event Consumer      │  ← Event Processing
└──────────────────────┘
```

- **Frontend**: Communicates only with the Backend For Frontend (BFF)
- **BFF**: Handles authentication (login, refresh token, logout), rate limiting, without domain business logic
- **User Service**: Responsible for user registration, user data storage, password hashing, and uniqueness validation
- **Event Consumer**: Processes events from Kafka (UserRegistered, etc.)
- **Event-driven**: Uses Apache Kafka for inter-service communication

## Tech Stack

- **Language**: Go 1.24
- **Database**: PostgreSQL 15+
- **Message Broker**: Apache Kafka (KRaft mode)
- **Containerization**: Docker + Docker Compose

## Framework & Library

| Library | Purpose |
|---------|---------|
| GoFiber | HTTP Framework |
| GORM | ORM |
| Viper | Configuration Management |
| Golang Migrate | Database Migration |
| Go Playground Validator | Validation |
| Logrus | Structured Logging |
| Kafka-Go | Kafka Client |
| JWT | Authentication |
| Testify | Testing Framework |

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Go 1.24+ (for development)

### Setup with Docker

1. Clone the repository:
```bash
git clone <repository-url>
cd go-event-driven
```

2. Build and run all services:
```bash
docker-compose up --build
```

3. Services will be available at:
   - BFF: http://localhost:8080
   - User Service: http://localhost:8081
   - PostgreSQL: localhost:5432
   - Kafka: localhost:9092

### Rebuild Single Service

If there are changes to a single service, rebuild without restarting all:

```bash
# Rebuild BFF only
docker-compose up -d --no-deps --build bff

# Rebuild User Service only
docker-compose up -d --no-deps --build user-service

# Rebuild Event Consumer only
docker-compose up -d --no-deps --build user-event-consumer
```

### Setup for Development

1. Setup project:
```bash
make setup
```

2. Start development environment:
```bash
make dev
```

3. Or manual setup:
```bash
# Install dependencies
go mod tidy

# Start PostgreSQL and Kafka
docker-compose up postgres kafka -d

# Run migrations
make migrate-up

# Start User Service
go run cmd/user-service/main.go

# Start BFF (in another terminal)
go run cmd/bff/main.go
```

### Available Make Commands

```bash
make help           # Show all available commands
make build          # Build all binaries
make test           # Run tests
make test-coverage  # Run tests with coverage
make lint           # Run linter
make fmt            # Format code
make run            # Run with Docker Compose
make dev            # Start development environment
make migrate-up     # Run database migrations
make migrate-down   # Rollback migrations
make health         # Check service health
```

## API Endpoints

### BFF Service (Port 8080)

#### Public Routes
| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| POST | `/api/v1/register` | Register new user | 3 req/min |
| POST | `/api/v1/auth/login` | Login user | 5 req/min |
| POST | `/api/v1/auth/refresh` | Refresh access token | 10 req/min |
| POST | `/api/v1/auth/logout` | Logout user | 5 req/min |
| GET | `/health` | Health check | - |

#### Protected Routes (Requires JWT)
| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| GET | `/api/v1/protected/profile` | Get user profile | 100 req/min |
| GET | `/api/v1/protected/admin/dashboard` | Admin dashboard (admin role) | 100 req/min |

### User Service (Port 8081) - Internal

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/register` | Register new user |
| POST | `/api/v1/verify-credentials` | Verify user credentials |
| GET | `/api/v1/users/:id` | Get user by ID |
| GET | `/health` | Health check |

## API Usage Examples

### Register User
```bash
curl -X POST http://localhost:8080/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "first_name": "John",
    "last_name": "Doe",
    "phone": "1234567890"
  }'
```

### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Access Protected Route
```bash
curl -X GET http://localhost:8080/api/v1/protected/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Refresh Token
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN"
  }'
```

### Rate Limit Response
When rate limit is exceeded:
```json
{
  "error": "Too many requests",
  "message": "Rate limit exceeded. Please try again later.",
  "retry_after": "60 seconds"
}
```
HTTP Status: `429 Too Many Requests`

## Configuration

This project supports configuration through YAML files and environment variables.

### Configuration Files

| File | Environment |
|------|-------------|
| `configs/config.development.yaml` | Development (local) |
| `configs/config.docker.yaml` | Docker |
| `configs/config.production.yaml` | Production |

### Environment Variables

Set `ENV` to select configuration:
```bash
ENV=development  # configs/config.development.yaml
ENV=production   # configs/config.production.yaml
ENV=docker       # configs/config.docker.yaml
```

### Available Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | Database host | localhost |
| `DB_PORT` | Database port | 5432 |
| `DB_NAME` | Database name | event_driven_db |
| `DB_USER` | Database username | postgres |
| `DB_PASSWORD` | Database password | - |
| `KAFKA_BROKERS` | Kafka brokers | localhost:9092 |
| `JWT_SECRET` | JWT secret key | - |
| `USER_SERVICE_URL` | User service URL (BFF) | http://localhost:8081 |
| `PORT` | Service port | 8080/8081 |
| `LOG_LEVEL` | Log level | info |

## Event Flow

### User Registration
```
1. Frontend → POST /register → BFF
2. BFF → User Service via HTTP
3. User Service:
   - Validate email/phone uniqueness
   - Hash password (bcrypt)
   - Save to database
   - Publish 'UserRegistered' event to Kafka
4. Event Consumer receives and processes the event
```

### User Login
```
1. Frontend → POST /login → BFF
2. BFF → User Service /verify-credentials
3. User Service returns {user_id, role, is_active, valid}
4. BFF generates JWT tokens
5. Response to Frontend
```

## Security Features

### Authentication & Authorization
- **Password Hashing**: bcrypt with default cost
- **JWT Access Token**: 1-24 hours expiry (configurable)
- **JWT Refresh Token**: 1-7 days expiry (configurable)
- **Role-based Authorization**: admin, user, etc.

### Rate Limiting
| Endpoint | Limit | Purpose |
|----------|-------|---------|
| `/api/v1/register` | 3 req/min | Prevent spam registration |
| `/api/v1/auth/login` | 5 req/min | Prevent brute force |
| `/api/v1/auth/refresh` | 10 req/min | Token refresh |
| `/api/v1/auth/logout` | 5 req/min | Logout |
| `/api/v1/protected/*` | 100 req/min | General API |

### Other Security
- Input validation with go-playground/validator
- CORS support
- Structured error responses

## Database Migration

### Using Makefile
```bash
make migrate-up              # Run migrations
make migrate-down            # Rollback migrations
make migrate-create name=xxx # Create new migration
make migrate-status          # Check status
```

### Using Script
```bash
./scripts/migrate.sh up
./scripts/migrate.sh down 1
./scripts/migrate.sh create add_new_table
./scripts/migrate.sh status
```

### Migration Files
```
migrations/
├── 000001_create_users_table.up.sql
├── 000001_create_users_table.down.sql
├── 000002_add_user_indexes.up.sql
└── 000002_add_user_indexes.down.sql
```

## Testing

### Run Tests
```bash
# Run all tests
go test ./... -v

# Run with coverage
go test ./... -v -cover

# Run specific package
go test ./internal/bff/... -v
go test ./internal/user-service/... -v
go test ./pkg/auth/... -v
go test ./pkg/ratelimit/... -v
```

### Test Coverage

| Package | Coverage |
|---------|----------|
| `internal/bff/handler` | ~88% |
| `internal/bff/service` | ~78% |
| `internal/user-service/handler` | 100% |
| `internal/user-service/service` | ✓ |
| `pkg/auth` | ✓ |
| `pkg/ratelimit` | ✓ |

### Test Structure
```
*_test.go files alongside source files:
├── internal/bff/handler/auth_handler_test.go
├── internal/bff/service/auth_service_test.go
├── internal/user-service/handler/user_handler_test.go
├── internal/user-service/service/user_service_test.go
├── pkg/auth/jwt_test.go
├── pkg/auth/middleware_test.go
└── pkg/ratelimit/ratelimit_test.go
```

## Project Structure

```
.
├── cmd/                          # Entry points
│   ├── bff/                      # BFF service
│   │   ├── main.go
│   │   └── Dockerfile
│   ├── user-service/             # User service
│   │   ├── main.go
│   │   └── Dockerfile
│   ├── user-event-consumer/      # Kafka consumer
│   │   ├── main.go
│   │   └── Dockerfile
│   └── migrate/                  # Migration tool
│       ├── main.go
│       └── Dockerfile
│
├── internal/                     # Private application code
│   ├── bff/
│   │   ├── handler/              # HTTP handlers + tests
│   │   ├── service/              # Business logic + tests
│   │   └── model/                # DTOs
│   ├── user-service/
│   │   ├── handler/              # HTTP handlers + tests
│   │   ├── service/              # Business logic + tests
│   │   ├── repository/           # Data access
│   │   └── model/                # Entities & DTOs
│   └── user-event-consumer/
│       └── service/              # Event handlers
│
├── pkg/                          # Public/shared packages
│   ├── auth/                     # JWT + Middleware + tests
│   ├── config/                   # Configuration
│   ├── database/                 # Database utilities
│   ├── kafka/                    # Kafka producer/consumer
│   ├── logger/                   # Structured logging
│   └── ratelimit/                # Rate limiting + tests
│
├── configs/                      # Configuration files
│   ├── config.development.yaml
│   ├── config.docker.yaml
│   └── config.production.yaml
│
├── migrations/                   # Database migrations
├── scripts/                      # Utility scripts
├── docker-compose.yml
├── Makefile
└── README.md
```

## Monitoring

### Health Checks
```bash
# BFF
curl http://localhost:8080/health

# User Service
curl http://localhost:8081/health
```

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f bff
docker-compose logs -f user-service
docker-compose logs -f user-event-consumer
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Kafka connection failed | Make sure Kafka is running: `docker-compose ps kafka` |
| Database connection failed | Check PostgreSQL: `docker-compose ps postgres` |
| JWT validation failed | Check JWT_SECRET in config |
| Rate limit hit | Wait 60 seconds or use a different IP |

### Debug Commands
```bash
# Check running containers
docker-compose ps

# View container logs
docker-compose logs -f [service-name]

# Restart specific service
docker-compose restart [service-name]

# Rebuild and restart
docker-compose up -d --no-deps --build [service-name]
```

## Contributing

1. Fork the project
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`go test ./...`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Create Pull Request

## License

MIT License
