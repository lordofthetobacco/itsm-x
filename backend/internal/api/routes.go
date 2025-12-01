package api

import (
	"github.com/gin-gonic/gin"
	"itsm.x/config"
)

var router *gin.Engine

func setupRoutes(router *gin.Engine) {
	router.GET("/health", GetHealth)

	authGroup := router.Group("/auth")
	{
		authGroup.POST("/login", Login)
		authGroup.POST("/register", Register)
		authGroup.POST("/refresh", Refresh)
		authGroup.POST("/logout", Logout)
	}

	protected := router.Group("/")
	protected.Use(AuthMiddleware())
	{
		protected.GET("/users", GetUsers)
		protected.GET("/users/:id", GetUser)
		protected.POST("/users", CreateUser)
		protected.PUT("/users/:id", UpdateUser)
		protected.DELETE("/users/:id", DeleteUser)
	}
}

func init() {
	if config.GetConfig().ServerConfig.Environment == "development" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	router = gin.Default()
	setupRoutes(router)
}

func GetRouter() *gin.Engine {
	return router
}
