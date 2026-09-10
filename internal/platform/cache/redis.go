package cache

import (
	"time"

	"github.com/redis/go-redis/v9"
)

// NewClient builds a Redis client with tight timeouts.
// Callers must handle ErrClosed / dial failures as degraded, not fatal.
func NewClient(url string) (*redis.Client, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	opt.DialTimeout = 3 * time.Second
	opt.ReadTimeout = 2 * time.Second
	opt.WriteTimeout = 2 * time.Second
	opt.PoolSize = 20
	return redis.NewClient(opt), nil
}
