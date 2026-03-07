# ADR-001: Asynq for Background Job Processing

## Status

Accepted

## Context

Go-Hunter requires robust background job processing for several core operations:

1. **Asset Discovery**: Fetching assets from cloud providers (AWS, GCP, Azure, etc.) involves multiple API calls that can take significant time and may be rate-limited by providers.

2. **Port Scanning**: Scanning thousands of ports across multiple hosts is inherently slow and should not block API responses.

3. **HTTP Probing**: Detecting web services requires making HTTP requests with timeouts, which can take minutes for large asset inventories.

4. **Web Crawling**: Recursively crawling web applications to discover endpoints is time-intensive.

5. **Scheduled Scans**: Users need the ability to schedule recurring scans (e.g., daily security audits).

The job queue must support:
- Reliable task execution with automatic retries
- Priority queues (security-critical scans vs. routine checks)
- Task scheduling (cron-like recurring jobs)
- Horizontal scaling (multiple workers)
- Visibility into queue state for debugging
- Clean Go API without excessive boilerplate

### Alternatives Considered

1. **gocraft/work** - Older library, less active maintenance
2. **Machinery** - Feature-rich but complex configuration, RabbitMQ/Redis support
3. **go-workers** - Sidekiq-compatible, simpler but fewer features
4. **Temporal** - Powerful workflow engine, overkill for our use case
5. **Native goroutines + channels** - Simple but lacks persistence, retries, visibility

## Decision

We chose **Asynq** (github.com/hibiken/asynq) as our background job queue.

### Implementation Details

**Queue Configuration** (`pkg/queue/queue.go`):
```go
func NewServer(cfg *config.RedisConfig, concurrency int) *asynq.Server {
    return asynq.NewServer(
        asynq.RedisClientOpt{
            Addr:     cfg.Addr(),
            Password: cfg.Password,
        },
        asynq.Config{
            Concurrency: concurrency,
            Queues: map[string]int{
                "critical": 6,  // Security-critical tasks
                "default":  3,  // Standard scans
                "low":      1,  // Background maintenance
            },
        },
    )
}
```

**Task Types** (`internal/tasks/types.go`):
```go
const (
    TypeAssetDiscovery = "scan:asset_discovery"
    TypePortScan       = "scan:port_scan"
    TypeHTTPProbe      = "scan:http_probe"
    TypeCrawl          = "scan:crawl"
    TypeVulnCheck      = "scan:vuln_check"
    TypeSchedulerTick  = "scheduler:tick"
)
```

**Scheduler Integration** (`cmd/worker/main.go`):
```go
scheduler := asynq.NewScheduler(
    asynq.RedisClientOpt{Addr: cfg.Redis.Addr()},
    nil,
)
// Run scheduler tick every minute to check for due scans
scheduler.Register("@every 1m", tasks.NewSchedulerTickTask())
```

**Task Handlers** (`internal/tasks/handlers.go`):
```go
func (h *Handler) RegisterHandlers(mux *asynq.ServeMux) {
    mux.HandleFunc(TypeAssetDiscovery, h.HandleAssetDiscovery)
    mux.HandleFunc(TypePortScan, h.HandlePortScan)
    mux.HandleFunc(TypeHTTPProbe, h.HandleHTTPProbe)
    mux.HandleFunc(TypeCrawl, h.HandleCrawl)
    mux.HandleFunc(TypeVulnCheck, h.HandleVulnCheck)
    mux.HandleFunc(TypeSchedulerTick, h.HandleSchedulerTick)
}
```

## Consequences

### Positive

1. **Simple, Clean API**: Asynq's API is straightforward and Go-idiomatic. Creating tasks is as simple as:
   ```go
   task := asynq.NewTask(TypePortScan, payload)
   client.Enqueue(task)
   ```

2. **Built-in Retry Logic**: Failed tasks are automatically retried with exponential backoff. No custom retry logic needed.

3. **Priority Queues**: The weighted queue system allows security-critical scans to take precedence:
   - `critical: 6` - 60% of worker capacity for urgent tasks
   - `default: 3` - 30% for standard scans
   - `low: 1` - 10% for background tasks

4. **Scheduler Integration**: Built-in cron-like scheduling eliminates the need for a separate scheduler service.

5. **Monitoring with Asynqmon**: Official web UI for queue inspection, task retry, and debugging.

6. **Graceful Shutdown**: Workers can finish in-flight tasks before shutting down:
   ```go
   srv.Shutdown()  // Waits for active tasks to complete
   ```

7. **Type-Safe Payloads**: JSON serialization with strong typing for task payloads.

### Negative

1. **Redis Dependency**: Asynq requires Redis, adding an infrastructure dependency. However, we already needed Redis for caching and rate limiting, so this is acceptable.

2. **Limited Message Broker Flexibility**: Unlike Machinery, Asynq only supports Redis (not RabbitMQ, SQS, etc.). For our scale, Redis is sufficient.

3. **No Built-in Dead Letter Queue Visibility**: Failed tasks after max retries need custom handling for alerting.

4. **Single Language**: Asynq is Go-only. If we ever need polyglot workers, we'd need a different solution.

### Operational Considerations

- **Redis Persistence**: Configure Redis with AOF or RDB for task durability
- **Worker Scaling**: Deploy multiple worker instances for horizontal scaling
- **Memory Management**: Monitor Redis memory usage with large job backlogs
- **Monitoring**: Deploy Asynqmon for production visibility

## References

- [Asynq GitHub Repository](https://github.com/hibiken/asynq)
- [Asynq Wiki](https://github.com/hibiken/asynq/wiki)
- [Asynqmon Web UI](https://github.com/hibiken/asynqmon)
