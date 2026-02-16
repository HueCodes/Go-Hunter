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
RUN addgroup -g 1000 gohunter && \
    adduser -D -u 1000 -G gohunter gohunter
COPY --from=builder /bin/server /bin/server
COPY --from=builder /app/migrations /app/migrations
RUN chown -R gohunter:gohunter /app /bin/server
WORKDIR /app
USER gohunter
EXPOSE 8080
CMD ["/bin/server"]

# Worker image
FROM alpine:3.20 AS worker
RUN apk add --no-cache ca-certificates tzdata libpcap
RUN addgroup -g 1000 gohunter && \
    adduser -D -u 1000 -G gohunter gohunter
COPY --from=builder /bin/worker /bin/worker
RUN chown -R gohunter:gohunter /app /bin/worker
WORKDIR /app
USER gohunter
CMD ["/bin/worker"]
