package database

import (
	"errors"
	"fmt"
	"log"
)

import (
	_ "gorm.io/driver/postgres"
)

type Database struct {
	PS *PostgresqlStorage
	R  *RedisStorage

	// Config
	postgresql *Postgresql
	redis      *Redis
}

func Init() (d *Database) {
	d = &Database{}
	log.Println("Checking config")
	_, err := d.RedisConfig()
	if err != nil {
		log.Fatal(errors.New(fmt.Sprintf("redis config error: %e", err)))
	}

	_, err = d.PostgresqlConfig()
	if err != nil {
		log.Fatal(errors.New(fmt.Sprintf("postgresql config error: %e", err)))
	}

	log.Println("Config is fine")
	return d
}

func (d *Database) Start() {
	log.Println("Start the database")

	_, _, err := d.setupStorage()
	if err != nil {
		log.Fatal(errors.New(fmt.Sprintf("setupStorage error: %e", err)))
	}
}

func (d *Database) setupStorage() (*PostgresqlStorage, *RedisStorage, error) {
	// Postgresql database
	postgresqlConf, err := d.PostgresqlConfig()
	if err != nil {
		return nil, nil, err
	}
	postgresqlDb, err := d.setupPostgresqlDatabase(postgresqlConf)
	if err != nil {
		return nil, nil, err
	}
	//err = postgresqlDb.RunMigrations()
	if err != nil {
		return nil, nil, err
	}

	//Redis database
	redisConf, err := d.RedisConfig()
	if err != nil {
		return nil, nil, err
	}
	redisDb, err := d.setupRedisDatabase(redisConf)
	if err != nil {
		return nil, nil, err
	}

	d.PS, d.R = postgresqlDb, redisDb
	return postgresqlDb, redisDb, nil
}
