package database

import (
	"fmt"
	"github.com/go-redis/redis"
	"os"
	"strconv"
)

// Config

type Redis struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Db       int    `json:"db"`
}

func (d *Database) RedisConfig() (*Redis, error) {
	host := os.Getenv("REDIS_HOST")
	port, err := strconv.Atoi(os.Getenv("REDIS_PORT"))
	if err != nil {
		return nil, err
	}
	pass := os.Getenv("REDIS_PASS")
	db, err := strconv.Atoi(os.Getenv("REDIS_DB"))
	if err != nil {
		return nil, err
	}
	data := Redis{
		Host:     host,
		Port:     port,
		Password: pass,
		Db:       db,
	}

	d.redis = &data
	return &data, nil
}

// App

type RedisStorage struct {
	DB     *redis.Client
	config *Redis
}

func (d *Database) redisStorage(db *redis.Client, config *Redis) *RedisStorage {
	return &RedisStorage{
		DB:     db,
		config: config,
	}
}

func (d *Database) setupRedisDatabase(conf *Redis) (*RedisStorage, error) {
	// Create new connection
	db := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", conf.Host, conf.Port),
		Password: conf.Password, // no password set
		DB:       conf.Db,       // use default DB
	})

	// Ping connection
	ping := db.Ping()
	if ping.Err() != nil {
		return nil, ping.Err()
	}

	return d.redisStorage(db, conf), nil
}
