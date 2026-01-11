package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	Database DatabaseConfig `mapstructure:"database"`
	Kafka    KafkaConfig    `mapstructure:"kafka"`
	Server   ServerConfig   `mapstructure:"server"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Services ServicesConfig `mapstructure:"services"`
}

type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Database string `mapstructure:"database"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"sslmode"`
}

type KafkaConfig struct {
	Brokers []string `mapstructure:"brokers"`
}

type ServerConfig struct {
	Port int `mapstructure:"port"`
}

type JWTConfig struct {
	Secret           string `mapstructure:"secret"`
	ExpirationHours  int    `mapstructure:"expiration_hours"`
	RefreshExpirationDays int `mapstructure:"refresh_expiration_days"`
}

type ServicesConfig struct {
	UserServiceURL string `mapstructure:"user_service_url"`
}

func LoadConfig() *Config {
	cfg, err := Load()
	if err != nil {
		panic(fmt.Sprintf("Failed to load config: %v", err))
	}
	return cfg
}

func (c *Config) KafkaBrokers() []string {
	return c.Kafka.Brokers
}

func Load() (*Config, error) {
	env := os.Getenv("ENV")
	if env == "" {
		env = "development"
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./configs")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, try environment specific config
			viper.SetConfigName(fmt.Sprintf("config.%s", env))
			if err := viper.ReadInConfig(); err != nil {
				if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
					return nil, fmt.Errorf("error reading config file: %w", err)
				}
			}
		} else {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	viper.AutomaticEnv()

	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.database", "event_driven_db")
	viper.SetDefault("database.username", "postgres")
	viper.SetDefault("database.password", "postgres123")
	viper.SetDefault("database.sslmode", "disable")

	viper.SetDefault("kafka.brokers", []string{"localhost:9092"})

	viper.SetDefault("server.port", 8080)

	viper.SetDefault("jwt.secret", "your-super-secret-jwt-key")
	viper.SetDefault("jwt.expiration_hours", 24)
	viper.SetDefault("jwt.refresh_expiration_days", 7)

	viper.SetDefault("services.user_service_url", "http://localhost:8081")

	viper.BindEnv("database.host", "DB_HOST")
	viper.BindEnv("database.port", "DB_PORT")
	viper.BindEnv("database.database", "DB_NAME")
	viper.BindEnv("database.username", "DB_USER")
	viper.BindEnv("database.password", "DB_PASSWORD")
	viper.BindEnv("kafka.brokers", "KAFKA_BROKERS")
	viper.BindEnv("server.port", "PORT")
	viper.BindEnv("jwt.secret", "JWT_SECRET")
	viper.BindEnv("services.user_service_url", "USER_SERVICE_URL")


	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	return &config, nil
}

func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.Username, d.Password, d.Database, d.SSLMode)
}