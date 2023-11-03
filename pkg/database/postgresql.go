package database

import (
	"fmt"
	"gorm.io/driver/postgres"
	"log"
	"os"
	"strconv"
	"time"

	gorm "gorm.io/gorm"

	_ "github.com/lib/pq"
)

// Config

type Postgresql struct {
	Host     string `json:"h"`
	Port     int    `json:"port"`
	Name     string `json:"n"`
	User     string `json:"u"`
	Password string `json:"p"`
}

func (d *Database) PostgresqlConfig() (*Postgresql, error) {
	host := os.Getenv("POSTGRES_HOST")
	port, err := strconv.Atoi(os.Getenv("POSTGRES_PORT"))
	if err != nil {
		return nil, err
	}
	user := os.Getenv("POSTGRES_USER")
	pass := os.Getenv("POSTGRES_PASSWORD")
	name := os.Getenv("POSTGRES_DB")

	data := Postgresql{
		Host:     host,
		Port:     port,
		User:     user,
		Password: pass,
		Name:     name,
	}

	d.postgresql = &data
	return &data, nil
}

// App

type PostgresqlStorage struct {
	Db               *gorm.DB
	config           *Postgresql
	connectionString string
}

func (d *Database) postgresqlStorage(db *gorm.DB, connectionString string, config *Postgresql) *PostgresqlStorage {
	return &PostgresqlStorage{
		Db:               db,
		config:           config,
		connectionString: connectionString,
	}
}

func (d *Database) setupPostgresqlDatabase(conf *Postgresql) (*PostgresqlStorage, error) {
	// Create connection string
	connString := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", conf.Host, conf.Port, conf.User, conf.Password, conf.Name)
	time.Sleep(3 * time.Second)

	// Set up gorm
	postgresConf := &gorm.Config{}
	db, err := gorm.Open(postgres.Open(connString), postgresConf)
	if err != nil {
		return nil, err
	}
	log.Println("Postgres database successfully ping")

	return d.postgresqlStorage(db, connString, conf), nil
}

func (s *PostgresqlStorage) Migration(val []interface{}) error {
	log.Print("Start migration")

	for _, v := range val {
		err := s.Db.AutoMigrate(&v)
		if err != nil {
			log.Println(fmt.Sprintf("%s migrate error - %e", v, err))
			return err
		}
	}

	log.Print("Migration complete")
	return nil
}
