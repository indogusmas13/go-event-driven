FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o user-service ./cmd/user-service


FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary
COPY --from=builder /app/user-service .

# Copy migrations
COPY --from=builder /app/migrations ./migrations

# Default command (serve)
CMD ["./user-service"]
