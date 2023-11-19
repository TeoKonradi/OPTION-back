package option

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func (core *Core) CorsDebugConfig() gin.HandlerFunc {
	// - All origin allowed by default
	// - All methods
	// - All headers
	// - Credentials share enabled
	// - Preflight requests cached for 12 hours

	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	config.AllowHeaders = []string{"*"}
	config.AllowMethods = []string{"*"}
	config.AllowCredentials = true
	return cors.New(config)
}

func (core *Core) CorsConfig() gin.HandlerFunc {
	// - No origin allowed by default
	// - GET,POST, PUT, HEAD methods
	// - Credentials share disabled
	// - Preflight requests cached for 12 hours

	config := cors.DefaultConfig()
	//config.AllowOrigins = []string{"*"}
	//config.AllowHeaders = []string{"*"}
	//config.AllowMethods = []string{"*"}
	//config.AllowCredentials = true
	return cors.New(config)
}
