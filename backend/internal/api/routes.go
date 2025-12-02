package api

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"itsm.x/config"
)

var router *gin.Engine

func setupRoutes(router *gin.Engine) {
	router.GET("/health", GetHealth)
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	router.MaxMultipartMemory = 8 << 20

	authGroup := router.Group("/auth")
	{
		authGroup.POST("/login", Login)
		authGroup.POST("/register", Register)
		authGroup.POST("/refresh", Refresh)
		authGroup.POST("/logout", Logout)
		authGroup.GET("/me", AuthMiddleware(), GetMe)
		authGroup.GET("/permissions", AuthMiddleware(), GetMyPermissions)
	}

	protected := router.Group("/")
	protected.Use(AuthMiddleware())
	{
		protected.GET("/ticket-statuses", GetTicketStatuses)
		protected.GET("/ticket-priorities", GetTicketPriorities)

		protected.GET("/roles", RequirePermission("roles.read"), GetRoles)
		protected.GET("/permissions", RequirePermission("permissions.read"), GetPermissions)

		protected.GET("/users", RequirePermission("users.read"), GetUsers)
		protected.GET("/users/:id", RequirePermission("users.read"), GetUser)
		protected.POST("/users", RequirePermission("users.create"), CreateUser)
		protected.PUT("/users/:id", RequirePermission("users.update"), UpdateUser)
		protected.DELETE("/users/:id", RequirePermission("users.delete"), DeleteUser)

		protected.POST("/users/:id/avatar", RequirePermission("users.update"), UploadUserAvatar)
		protected.GET("/users/:id/avatar", GetUserAvatar)
		protected.DELETE("/users/:id/avatar", RequirePermission("users.update"), DeleteUserAvatar)

		protected.GET("/tickets", RequirePermission("tickets.read"), GetTickets)
		protected.GET("/tickets/:id", RequirePermission("tickets.read"), GetTicket)
		protected.POST("/tickets", RequirePermission("tickets.create"), CreateTicket)
		protected.PUT("/tickets/:id", RequirePermission("tickets.update"), UpdateTicket)
		protected.DELETE("/tickets/:id", RequirePermission("tickets.delete"), DeleteTicket)
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
