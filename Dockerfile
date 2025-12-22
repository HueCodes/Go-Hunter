# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/server ./cmd/server

# Build worker
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/worker ./cmd/worker

# Server image
FROM alpine:3.20 AS server
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/server /bin/server
COPY --from=builder /app/migrations /app/migrations
WORKDIR /app
EXPOSE 8080
CMD ["/bin/server"]

# Worker image
FROM alpine:3.20 AS worker
RUN apk add --no-cache ca-certificates tzdata libpcap
COPY --from=builder /bin/worker /bin/worker
WORKDIR /app
CMD ["/bin/worker"]
