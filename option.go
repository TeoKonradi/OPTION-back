package option

import (
	"github.com/gin-gonic/gin"
	"github.com/wawilow108/option/pkg/config"
	"github.com/wawilow108/option/pkg/database"
)

type Core struct {
	Router  *gin.Engine
	Session *config.Session

	ActiveTag   []string
	Permissions []string
}

func New() (core *Core) {
	core = &Core{
		Router: gin.Default(),

		ActiveTag:   []string{},
		Permissions: []string{},
	}
	return core
}

func Default(session *config.Session) (Core *Core) {
	core := New()
	if session.Config.Debug {
		core.Router.Use(core.CorsDebugConfig())
	} else {
		core.Router.Use(core.CorsConfig())
	}

	if session.Config.Database == nil {
		session.Config.Database = database.Init()
		session.Config.Database.Start()
	}

	if session.Config.LoggerMiddleware != "" {
		core.Router.Use(core.LogMiddleware)
	}

	core.Session = session
	return core
}
