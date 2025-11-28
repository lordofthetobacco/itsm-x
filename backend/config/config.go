package config

import "os"

type Config struct {
	DBURL       string
	Port        string
	Environment string
	LogLevel    string
}

var config *Config

func init() {
	config = &Config{
		DBURL:       os.Getenv("DATABASE_URL"),
		Port:        os.Getenv("PORT"),
		Environment: os.Getenv("ENVIRONMENT"),
		LogLevel:    os.Getenv("LOG_LEVEL"),
	}
}

func GetConfig() *Config {
	return config
}
