package api

import (
	"github.com/gin-gonic/gin"
	"itsm.x/config"
)

var router *gin.Engine

func setupRoutes(router *gin.Engine) {
	router.GET("/health", GetHealth)
	router.GET("/users", GetUsers)
	router.GET("/users/:id", GetUser)
	router.POST("/users", CreateUser)
	router.PUT("/users/:id", UpdateUser)
	router.DELETE("/users/:id", DeleteUser)
}

func init() {
	gin.SetMode(config.GetConfig().ServerConfig.Environment)
	router = gin.Default()
	setupRoutes(router)
}

func GetRouter() *gin.Engine {
	return router
}
