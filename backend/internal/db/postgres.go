package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
		&Role{},
		&Permission{},
		&RolePermission{},
		&User{},
		&TicketStatus{},
		&TicketPriority{},
		&Ticket{},
		&Comment{},
		&RefreshToken{},
	); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	if err := SeedRoles(ctx); err != nil {
		return fmt.Errorf("failed to seed roles: %w", err)
	}

	if err := SeedPermissions(ctx); err != nil {
		return fmt.Errorf("failed to seed permissions: %w", err)
	}

	if err := SeedRolePermissions(ctx); err != nil {
		return fmt.Errorf("failed to seed role permissions: %w", err)
	}

	if err := SeedTicketStatuses(ctx); err != nil {
		return fmt.Errorf("failed to seed ticket statuses: %w", err)
	}

	if err := SeedTicketPriorities(ctx); err != nil {
		return fmt.Errorf("failed to seed ticket priorities: %w", err)
	}

	if err := SeedAdminUser(ctx); err != nil {
		return fmt.Errorf("failed to seed admin user: %w", err)
	}

	return nil
}

func SeedRoles(ctx context.Context) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	roles := map[uint]struct {
		name        string
		description string
	}{
		1: {"admin", "Administrator with full system access"},
		2: {"manager", "Manager with elevated permissions"},
		3: {"agent", "Support agent with ticket management permissions"},
		4: {"user", "Regular user with basic permissions"},
	}

	for id, roleData := range roles {
		var existing Role
		err := db.WithContext(ctx).Where("id = ?", id).First(&existing).Error

		if errors.Is(err, gorm.ErrRecordNotFound) {
			role := Role{
				ID:          id,
				Name:        roleData.name,
				Description: roleData.description,
				CreatedAt:   time.Now(),
			}
			if err := db.WithContext(ctx).Create(&role).Error; err != nil {
				return fmt.Errorf("failed to create role %d (%s): %w", id, roleData.name, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to check role %d: %w", id, err)
		} else {
			if existing.Name != roleData.name || existing.Description != roleData.description {
				if err := db.WithContext(ctx).Model(&Role{}).Where("id = ?", id).Updates(map[string]interface{}{
					"name":        roleData.name,
					"description": roleData.description,
				}).Error; err != nil {
					return fmt.Errorf("failed to update role %d (%s): %w", id, roleData.name, err)
				}
			}
		}
	}

	return nil
}

func SeedPermissions(ctx context.Context) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	permissions := []struct {
		name        string
		resource    string
		action      string
		description string
	}{
		{"tickets.create", "tickets", "create", "Create new tickets"},
		{"tickets.read", "tickets", "read", "View tickets"},
		{"tickets.update", "tickets", "update", "Update tickets"},
		{"tickets.delete", "tickets", "delete", "Delete tickets"},
		{"tickets.assign", "tickets", "assign", "Assign tickets to users"},
		{"users.create", "users", "create", "Create new users"},
		{"users.read", "users", "read", "View users"},
		{"users.update", "users", "update", "Update users"},
		{"users.delete", "users", "delete", "Delete users"},
		{"comments.create", "comments", "create", "Create comments"},
		{"comments.update", "comments", "update", "Update comments"},
		{"comments.delete", "comments", "delete", "Delete comments"},
		{"roles.read", "roles", "read", "View roles"},
		{"permissions.read", "permissions", "read", "View permissions"},
	}

	for _, permData := range permissions {
		var existing Permission
		err := db.WithContext(ctx).Where("name = ?", permData.name).First(&existing).Error

		if errors.Is(err, gorm.ErrRecordNotFound) {
			permission := Permission{
				Name:        permData.name,
				Resource:    permData.resource,
				Action:      permData.action,
				Description: permData.description,
				CreatedAt:   time.Now(),
			}
			if err := db.WithContext(ctx).Create(&permission).Error; err != nil {
				return fmt.Errorf("failed to create permission %s: %w", permData.name, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to check permission %s: %w", permData.name, err)
		}
	}

	return nil
}

func SeedRolePermissions(ctx context.Context) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	rolePermissions := map[string][]string{
		"admin": {
			"tickets.create", "tickets.read", "tickets.update", "tickets.delete", "tickets.assign",
			"users.create", "users.read", "users.update", "users.delete",
			"comments.create", "comments.update", "comments.delete",
			"roles.read", "permissions.read",
		},
		"manager": {
			"tickets.create", "tickets.read", "tickets.update", "tickets.delete", "tickets.assign",
			"users.read", "users.update",
			"comments.create", "comments.update", "comments.delete",
			"roles.read", "permissions.read",
		},
		"agent": {
			"tickets.create", "tickets.read", "tickets.update", "tickets.assign",
			"users.read",
			"comments.create", "comments.update", "comments.delete",
		},
		"user": {
			"tickets.create", "tickets.read",
			"comments.create", "comments.update", "comments.delete",
		},
	}

	for roleName, permissionNames := range rolePermissions {
		var role Role
		if err := db.WithContext(ctx).Where("name = ?", roleName).First(&role).Error; err != nil {
			return fmt.Errorf("failed to find role %s: %w", roleName, err)
		}

		for _, permName := range permissionNames {
			var permission Permission
			if err := db.WithContext(ctx).Where("name = ?", permName).First(&permission).Error; err != nil {
				return fmt.Errorf("failed to find permission %s: %w", permName, err)
			}

			var existing RolePermission
			err := db.WithContext(ctx).Where("role_id = ? AND permission_id = ?", role.ID, permission.ID).First(&existing).Error

			if errors.Is(err, gorm.ErrRecordNotFound) {
				rolePerm := RolePermission{
					RoleID:       role.ID,
					PermissionID: permission.ID,
					CreatedAt:    time.Now(),
				}
				if err := db.WithContext(ctx).Create(&rolePerm).Error; err != nil {
					return fmt.Errorf("failed to create role permission %s -> %s: %w", roleName, permName, err)
				}
			} else if err != nil {
				return fmt.Errorf("failed to check role permission %s -> %s: %w", roleName, permName, err)
			}
		}
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

	var adminRole Role
	if err := db.WithContext(ctx).Where("name = ?", "admin").First(&adminRole).Error; err != nil {
		return fmt.Errorf("failed to find admin role: %w", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	adminUser := User{
		Name:         "Admin",
		Email:        "admin@itsm.x",
		PasswordHash: string(hashedPassword),
		RoleID:       adminRole.ID,
		CreatedAt:    time.Now(),
	}

	if err := db.WithContext(ctx).Create(&adminUser).Error; err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	log.Println("Created default admin user with login 'admin' and password 'admin'")
	return nil
}

func SeedTicketStatuses(ctx context.Context) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	statuses := map[uint]string{
		1: "Open",
		2: "Closed",
		3: "Closed Complete",
		4: "In Progress",
		5: "Resolved",
		6: "Cancelled",
	}

	for id, statusName := range statuses {
		var existing TicketStatus
		err := db.WithContext(ctx).Where("id = ?", id).First(&existing).Error

		if errors.Is(err, gorm.ErrRecordNotFound) {
			status := TicketStatus{
				ID:        id,
				Name:      statusName,
				CreatedAt: time.Now(),
			}
			if err := db.WithContext(ctx).Create(&status).Error; err != nil {
				return fmt.Errorf("failed to create ticket status %d (%s): %w", id, statusName, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to check ticket status %d: %w", id, err)
		} else {
			if existing.Name != statusName {
				if err := db.WithContext(ctx).Model(&TicketStatus{}).Where("id = ?", id).Update("name", statusName).Error; err != nil {
					return fmt.Errorf("failed to update ticket status %d (%s): %w", id, statusName, err)
				}
			}
		}
	}

	return nil
}

func SeedTicketPriorities(ctx context.Context) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	priorities := map[uint]string{
		1: "Low",
		2: "Medium",
		3: "High",
		4: "Critical",
	}

	for id, priorityName := range priorities {
		var existing TicketPriority
		err := db.WithContext(ctx).Where("id = ?", id).First(&existing).Error

		if errors.Is(err, gorm.ErrRecordNotFound) {
			priority := TicketPriority{
				ID:        id,
				Name:      priorityName,
				CreatedAt: time.Now(),
			}
			if err := db.WithContext(ctx).Create(&priority).Error; err != nil {
				return fmt.Errorf("failed to create ticket priority %d (%s): %w", id, priorityName, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to check ticket priority %d: %w", id, err)
		} else {
			if existing.Name != priorityName {
				if err := db.WithContext(ctx).Model(&TicketPriority{}).Where("id = ?", id).Update("name", priorityName).Error; err != nil {
					return fmt.Errorf("failed to update ticket priority %d (%s): %w", id, priorityName, err)
				}
			}
		}
	}

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
	if err := db.WithContext(ctx).Preload("Role").Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	return users, nil
}

func GetUserByID(ctx context.Context, id uint) (*User, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var user User
	if err := db.WithContext(ctx).Preload("Role").First(&user, id).Error; err != nil {
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

func GetUserByEmail(ctx context.Context, email string) (*User, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var user User
	if err := db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

func ValidatePassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func hashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func CreateRefreshToken(ctx context.Context, userID uint, token string, expiresAt time.Time) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	hashedToken := hashRefreshToken(token)

	refreshToken := RefreshToken{
		UserID:    userID,
		Token:     hashedToken,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	if err := db.WithContext(ctx).Create(&refreshToken).Error; err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}

	return nil
}

func GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	hashedToken := hashRefreshToken(token)

	var refreshToken RefreshToken
	if err := db.WithContext(ctx).Where("token = ? AND expires_at > ?", hashedToken, time.Now()).First(&refreshToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("refresh token not found or expired")
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	return &refreshToken, nil
}

func DeleteRefreshToken(ctx context.Context, token string) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	refreshToken, err := GetRefreshToken(ctx, token)
	if err != nil {
		return err
	}

	if err := db.WithContext(ctx).Delete(refreshToken).Error; err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

func DeleteUserRefreshTokens(ctx context.Context, userID uint) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	if err := db.WithContext(ctx).Where("user_id = ?", userID).Delete(&RefreshToken{}).Error; err != nil {
		return fmt.Errorf("failed to delete user refresh tokens: %w", err)
	}

	return nil
}

func GetRoleByID(ctx context.Context, id uint) (*Role, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var role Role
	if err := db.WithContext(ctx).First(&role, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("role not found")
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	return &role, nil
}

func GetRoleByName(ctx context.Context, name string) (*Role, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var role Role
	if err := db.WithContext(ctx).Where("name = ?", name).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("role not found: %s", name)
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	return &role, nil
}

func GetAllRoles(ctx context.Context) ([]Role, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var roles []Role
	if err := db.WithContext(ctx).Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}

	return roles, nil
}

func GetAllPermissions(ctx context.Context) ([]Permission, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var permissions []Permission
	if err := db.WithContext(ctx).Find(&permissions).Error; err != nil {
		return nil, fmt.Errorf("failed to get permissions: %w", err)
	}

	return permissions, nil
}

func GetUserPermissions(ctx context.Context, userID uint) ([]string, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var user User
	if err := db.WithContext(ctx).Preload("Role").First(&user, userID).Error; err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	var permissions []Permission
	if err := db.WithContext(ctx).
		Table("permissions").
		Joins("INNER JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Where("role_permissions.role_id = ?", user.RoleID).
		Find(&permissions).Error; err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	permissionNames := make([]string, len(permissions))
	for i, perm := range permissions {
		permissionNames[i] = perm.Name
	}

	return permissionNames, nil
}

func CheckUserPermission(ctx context.Context, userID uint, permissionName string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("database connection not initialized")
	}

	var count int64
	err := db.WithContext(ctx).
		Table("role_permissions").
		Joins("INNER JOIN users ON role_permissions.role_id = users.role_id").
		Joins("INNER JOIN permissions ON role_permissions.permission_id = permissions.id").
		Where("users.id = ? AND permissions.name = ?", userID, permissionName).
		Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("failed to check user permission: %w", err)
	}

	return count > 0, nil
}

func GetTickets(ctx context.Context) ([]Ticket, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var tickets []Ticket
	if err := db.WithContext(ctx).Preload("Status").Preload("Priority").Preload("Requester").Preload("Assignee").Find(&tickets).Error; err != nil {
		return nil, fmt.Errorf("failed to get tickets: %w", err)
	}

	return tickets, nil
}

func GetTicketByID(ctx context.Context, id uint) (*Ticket, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var ticket Ticket
	if err := db.WithContext(ctx).Preload("Status").Preload("Priority").Preload("Requester").Preload("Assignee").Preload("Comments").Preload("Comments.User").First(&ticket, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("ticket not found")
		}
		return nil, fmt.Errorf("failed to get ticket: %w", err)
	}

	return &ticket, nil
}

func GetTicketStatusByName(ctx context.Context, name string) (*TicketStatus, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var status TicketStatus
	if err := db.WithContext(ctx).Where("name = ?", name).First(&status).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("ticket status not found: %s", name)
		}
		return nil, fmt.Errorf("failed to get ticket status: %w", err)
	}

	return &status, nil
}

func GetTicketPriorityByName(ctx context.Context, name string) (*TicketPriority, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var priority TicketPriority
	if err := db.WithContext(ctx).Where("name = ?", name).First(&priority).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("ticket priority not found: %s", name)
		}
		return nil, fmt.Errorf("failed to get ticket priority: %w", err)
	}

	return &priority, nil
}

func GetAllTicketStatuses(ctx context.Context) ([]TicketStatus, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var statuses []TicketStatus
	if err := db.WithContext(ctx).Find(&statuses).Error; err != nil {
		return nil, fmt.Errorf("failed to get ticket statuses: %w", err)
	}

	return statuses, nil
}

func GetAllTicketPriorities(ctx context.Context) ([]TicketPriority, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection not initialized")
	}

	var priorities []TicketPriority
	if err := db.WithContext(ctx).Find(&priorities).Error; err != nil {
		return nil, fmt.Errorf("failed to get ticket priorities: %w", err)
	}

	return priorities, nil
}

func CreateTicket(ctx context.Context, ticket *Ticket) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	ticket.CreatedAt = time.Now()
	ticket.UpdatedAt = time.Now()

	if err := db.WithContext(ctx).Create(ticket).Error; err != nil {
		return fmt.Errorf("failed to create ticket: %w", err)
	}

	return nil
}

func UpdateTicket(ctx context.Context, id uint, updates map[string]interface{}) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	updates["updated_at"] = time.Now()

	if err := db.WithContext(ctx).Model(&Ticket{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update ticket: %w", err)
	}

	return nil
}

func DeleteTicket(ctx context.Context, id uint) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	if err := db.WithContext(ctx).Delete(&Ticket{}, id).Error; err != nil {
		return fmt.Errorf("failed to delete ticket: %w", err)
	}

	return nil
}
