FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o bff ./cmd/bff

FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

# Copy the binary
COPY --from=builder /app/bff .

# Copy migrations directory (in case BFF needs it in the future)
COPY --from=builder /app/migrations ./migrations

CMD ["./bff"]