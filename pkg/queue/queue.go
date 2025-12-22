package queue

import (
	"github.com/hibiken/asynq"
	"github.com/hugh/go-hunter/pkg/config"
)

func NewClient(cfg *config.RedisConfig) *asynq.Client {
	return asynq.NewClient(asynq.RedisClientOpt{
		Addr:     cfg.Addr(),
		Password: cfg.Password,
	})
}

func NewServer(cfg *config.RedisConfig, concurrency int) *asynq.Server {
	if concurrency <= 0 {
		concurrency = 10
	}

	return asynq.NewServer(
		asynq.RedisClientOpt{
			Addr:     cfg.Addr(),
			Password: cfg.Password,
		},
		asynq.Config{
			Concurrency: concurrency,
			Queues: map[string]int{
				"critical": 6,
				"default":  3,
				"low":      1,
			},
		},
	)
}

func NewInspector(cfg *config.RedisConfig) *asynq.Inspector {
	return asynq.NewInspector(asynq.RedisClientOpt{
		Addr:     cfg.Addr(),
		Password: cfg.Password,
	})
}
