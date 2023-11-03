package config

import (
	"log"
	"os"
	"time"

	database "github.com/wawilow108/option/pkg/database"
)

// Config option config
type Config struct {
	// Data
	Debug        bool
	SSL          bool
	Active       bool
	Version      string
	BasePath     string
	AllowedHosts []string
	Data         Data

	// Active
	Database *database.Database
	Logger   *log.Logger

	// NowFunc the function to be used when creating a new timestamp
	NowFunc func() time.Time

	// Extensions TODO
	Extensions []interface{}
}

type Data struct {
	SiteTitle  string
	SiteHeader string
	SiteBrand  string
	SiteLogo   string
	Copyright  string
}

type Contact struct {
	Name  string
	Email string
	Url   string
}

// Session config when create session with Session() method
type Session struct {
	DryRun      bool
	Initialized bool

	Config *Config
}

func NewSession(session *Session) (se *Session) {
	se.DryRun = true
	se.Initialized = false

	if session.Config.Database != nil {
		d := database.Init()
		d.Start()
		session.Config.Database = d
	}

	if session.Config.Logger != nil {
		session.Config.Logger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	}

	if session.Config.NowFunc == nil {
		session.Config.NowFunc = func() time.Time { return time.Now().Local() }
	}

	se.Initialized = true
	return se
}

func (s *Session) ApplyConfig(config *Config) error {
	if config != s.Config {
		*config = *s.Config
	}
	return nil
}
