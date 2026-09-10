package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config is validated at startup. Fail fast on bad env.
type Config struct {
	Env         string
	Port        int
	DatabaseURL string
	RedisURL    string
	JWTSecret   []byte
	LogLevel    string
}

func Load() (Config, error) {
	c := Config{
		Env:         envOr("APP_ENV", "dev"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		RedisURL:    envOr("REDIS_URL", "redis://localhost:6379/0"),
		LogLevel:    envOr("LOG_LEVEL", "info"),
	}
	portStr := envOr("PORT", "8080")
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return Config{}, fmt.Errorf("invalid PORT %q", portStr)
	}
	c.Port = p
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		if c.Env == "prod" {
			return Config{}, fmt.Errorf("JWT_SECRET required in prod")
		}
		secret = "dev-only-insecure-secret-change-me-32b-min"
	}
	if len(secret) < 32 {
		return Config{}, fmt.Errorf("JWT_SECRET must be >= 32 chars")
	}
	c.JWTSecret = []byte(secret)
	return c, nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
