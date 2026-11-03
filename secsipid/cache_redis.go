package secsipid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	defaultRedisKeyPrefix = "secsipidx:cert:"
	defaultRedisTimeout   = 3
)

type redisURLCache struct {
	client    *redis.Client
	expire    time.Duration
	keyPrefix string
	timeout   time.Duration
	storeURL  bool
}

var _ urlCache = (*redisURLCache)(nil)

func newRedisURLCache(redisURL string, keyPrefix string, expire int,
	timeout int, storeURL bool) (*redisURLCache, error) {
	if redisURL == "" {
		return nil, errors.New("Redis URL is required")
	}
	if expire <= 0 {
		return nil, errors.New("Redis cache expiration must be positive")
	}
	if timeout <= 0 {
		return nil, errors.New("Redis timeout must be positive")
	}

	options, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, errors.New("invalid Redis URL")
	}
	timeoutDuration := time.Duration(timeout) * time.Second
	options.DialTimeout = timeoutDuration
	options.ReadTimeout = timeoutDuration
	options.WriteTimeout = timeoutDuration
	options.ContextTimeoutEnabled = true
	if keyPrefix == "" {
		keyPrefix = defaultRedisKeyPrefix
	}

	return &redisURLCache{
		client:    redis.NewClient(options),
		expire:    time.Duration(expire) * time.Second,
		keyPrefix: keyPrefix,
		timeout:   timeoutDuration,
		storeURL:  storeURL,
	}, nil
}

func validRedisURL(redisURL string) bool {
	if redisURL == "" {
		return true
	}
	_, err := redis.ParseURL(redisURL)
	return err == nil
}

func (c *redisURLCache) key(urlVal string) string {
	hashVal := sha256.Sum256([]byte(urlVal))
	return c.keyPrefix + hex.EncodeToString(hashVal[:])
}

func (c *redisURLCache) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.timeout)
}

func (c *redisURLCache) Get(ctx context.Context, urlVal string) ([]byte, error) {
	ctx, cancel := c.operationContext(ctx)
	defer cancel()

	data, err := c.client.Get(ctx, c.key(urlVal)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	return data, err
}

func (c *redisURLCache) Set(ctx context.Context, urlVal string, data []byte) error {
	ctx, cancel := c.operationContext(ctx)
	defer cancel()

	key := c.key(urlVal)
	if !c.storeURL {
		return c.client.Set(ctx, key, data, c.expire).Err()
	}
	_, err := c.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, key, data, c.expire)
		pipe.Set(ctx, key+":url", urlVal, c.expire)
		return nil
	})
	return err
}

func (c *redisURLCache) Close() error {
	return c.client.Close()
}
