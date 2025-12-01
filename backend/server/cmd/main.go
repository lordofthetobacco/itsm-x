package main

import (
	"context"
	"fmt"

	"itsm.x/config"
	"itsm.x/internal/api"
	"itsm.x/internal/db"
)

func main() {
	fmt.Println("Starting server...")
	db.InitDB()
	db.Migrate(context.Background())
	db.SeedAdminUser(context.Background())
	fmt.Println("Admin user created")
	defer db.Close()
	router := api.GetRouter()
	router.Run(fmt.Sprintf("%s:%s", "127.0.0.1", config.GetConfig().ServerConfig.Port))
	fmt.Println("Server started on port", config.GetConfig().ServerConfig.Port)
}
