package store

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Redis struct {
	cli *redis.Client
}

func NewRedis(ctx context.Context, addr, password string) (*Redis, error) {
	cli := redis.NewClient(&redis.Options{Addr: addr, Password: password})
	if err := cli.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return &Redis{cli: cli}, nil
}

func (r *Redis) Close() error { return r.cli.Close() }

func (r *Redis) Ping(ctx context.Context) error { return r.cli.Ping(ctx).Err() }

func (r *Redis) Claim(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return r.cli.SetNX(ctx, key, "1", ttl).Result()
}

func (r *Redis) IsDenied(ctx context.Context, jti string) (bool, error) {
	n, err := r.cli.Exists(ctx, "jti:denylist:"+jti).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (r *Redis) Deny(ctx context.Context, jti string, ttl time.Duration) error {
	return r.cli.Set(ctx, "jti:denylist:"+jti, "1", ttl).Err()
}

var rateScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
if c == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
if c > tonumber(ARGV[2]) then
  return 0
end
return 1
`)

func (r *Redis) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	res, err := rateScript.Run(ctx, r.cli, []string{"rl:" + key}, window.Milliseconds(), limit).Int()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

func (r *Redis) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	n, err := r.cli.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if n == 1 {
		_ = r.cli.Expire(ctx, key, ttl).Err()
	}
	return n, nil
}

func (r *Redis) Get(ctx context.Context, key string) (int64, error) {
	v, err := r.cli.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return v, err
}
