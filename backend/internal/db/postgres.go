package db

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"itsm.x/config"
)

func buildConnectionString() string {
	dbConfig := config.GetConfig().DbConfig
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", dbConfig.Host, dbConfig.Port, dbConfig.User, dbConfig.Password, dbConfig.DbName, dbConfig.SSLMode)
}

var db *gorm.DB

func GetDB() *gorm.DB {
	if db == nil {
		InitDB()
	}
	return db
}

func InitDB() {
	var err error
	db, err = gorm.Open(postgres.Open(buildConnectionString()), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("failed to get underlying sql.DB: %v", err)
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
}

func Migrate(ctx context.Context) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	if err := db.WithContext(ctx).AutoMigrate(
		&User{},
		&Ticket{},
		&Comment{},
	); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	if err := SeedAdminUser(ctx); err != nil {
		return fmt.Errorf("failed to seed admin user: %w", err)
	}

	return nil
}

func SeedAdminUser(ctx context.Context) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	var count int64
	if err := db.WithContext(ctx).Model(&User{}).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to count users: %w", err)
	}

	if count > 0 {
		return nil
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	adminUser := User{
		Name:         "Admin",
		Email:        "admin",
		PasswordHash: string(hashedPassword),
		Role:         "admin",
		CreatedAt:    time.Now(),
	}

	if err := db.WithContext(ctx).Create(&adminUser).Error; err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	log.Println("Created default admin user with login 'admin' and password 'admin'")
	return nil
}

func Close() error {
	if db == nil {
		return nil
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	return sqlDB.Close()
}

func GetUsers(ctx context.Context) ([]User, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var users []User
	if err := db.WithContext(ctx).Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	return users, nil
}

func GetUserByID(ctx context.Context, id uint) (*User, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var user User
	if err := db.WithContext(ctx).First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

func CreateUser(ctx context.Context, user *User) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	if user.PasswordHash != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.PasswordHash), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		user.PasswordHash = string(hashedPassword)
	}

	user.CreatedAt = time.Now()

	if err := db.WithContext(ctx).Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func UpdateUser(ctx context.Context, id uint, updates map[string]interface{}) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	if password, ok := updates["password"].(string); ok && password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		updates["password_hash"] = string(hashedPassword)
		delete(updates, "password")
	}

	if err := db.WithContext(ctx).Model(&User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func DeleteUser(ctx context.Context, id uint) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	if err := db.WithContext(ctx).Delete(&User{}, id).Error; err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}
