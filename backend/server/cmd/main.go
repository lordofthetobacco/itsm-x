package main

import (
	"fmt"

	"itsm.x/config"
	"itsm.x/internal/api"
	"itsm.x/internal/db"
)

func main() {
	fmt.Println("Starting server...")
	db.InitDB()
	defer db.Close()
	router := api.GetRouter()
	router.Run(fmt.Sprintf("%s:%s", "127.0.0.1", config.GetConfig().ServerConfig.Port))
	fmt.Println("Server started on port", config.GetConfig().ServerConfig.Port)
}
