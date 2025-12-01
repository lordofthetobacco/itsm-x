package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DbConfig     DbConfig     `yaml:"db"`
	ServerConfig ServerConfig `yaml:"server"`
	JWTConfig    JWTConfig    `yaml:"jwt"`
}

type DbConfig struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DbName   string `yaml:"db_name"`
	SSLMode  string `yaml:"ssl_mode"`
}

type ServerConfig struct {
	Port        string `yaml:"port"`
	Environment string `yaml:"environment"`
	LogLevel    string `yaml:"log_level"`
}

type JWTConfig struct {
	Secret                 string `yaml:"secret"`
	ExpirationHours        int    `yaml:"expiration_hours"`
	RefreshExpirationHours int    `yaml:"refresh_expiration_hours"`
}

var config *Config

func init() {
	configFile, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("failed to read config file: %v", err)
	}
	if err := yaml.Unmarshal(configFile, &config); err != nil {
		log.Fatalf("failed to unmarshal config: %v", err)
	}
}

func GetConfig() *Config {
	return config
}
