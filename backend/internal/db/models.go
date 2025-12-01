package db

import "time"

type Role struct {
	ID          uint      `gorm:"primaryKey"`
	Name        string    `gorm:"uniqueIndex;not null" json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	Users       []User    `gorm:"foreignKey:RoleID"`
}

type Permission struct {
	ID          uint      `gorm:"primaryKey"`
	Name        string    `gorm:"uniqueIndex;not null" json:"name"`
	Resource    string    `gorm:"not null;index" json:"resource"`
	Action      string    `gorm:"not null;index" json:"action"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	Roles       []Role    `gorm:"many2many:role_permissions;"`
}

type RolePermission struct {
	RoleID       uint       `gorm:"primaryKey;index" json:"role_id"`
	PermissionID uint       `gorm:"primaryKey;index" json:"permission_id"`
	CreatedAt    time.Time  `json:"created_at"`
	Role         Role       `gorm:"foreignKey:RoleID" json:"role,omitempty"`
	Permission   Permission `gorm:"foreignKey:PermissionID" json:"permission,omitempty"`
}

type User struct {
	ID           uint      `gorm:"primaryKey"`
	Name         string    `json:"name"`
	Email        string    `gorm:"uniqueIndex" json:"email"`
	PasswordHash string    `json:"-"`
	RoleID       uint      `gorm:"not null;index" json:"role_id"`
	Role         Role      `gorm:"foreignKey:RoleID" json:"role,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	Tickets      []Ticket  `gorm:"foreignKey:RequesterID"`
}

type TicketStatus struct {
	ID        uint      `gorm:"primaryKey"`
	Name      string    `gorm:"uniqueIndex;not null" json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type TicketPriority struct {
	ID        uint      `gorm:"primaryKey"`
	Name      string    `gorm:"uniqueIndex;not null" json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Ticket struct {
	ID          uint   `gorm:"primaryKey"`
	Title       string `json:"title"`
	Description string `json:"description"`

	StatusID uint         `gorm:"not null;index" json:"status_id"`
	Status   TicketStatus `gorm:"foreignKey:StatusID" json:"status,omitempty"`

	PriorityID uint           `gorm:"not null;index" json:"priority_id"`
	Priority   TicketPriority `gorm:"foreignKey:PriorityID" json:"priority,omitempty"`

	RequesterID uint `json:"requester_id"`
	Requester   User `gorm:"foreignKey:RequesterID" json:"requester,omitempty"`

	AssigneeID *uint `json:"assignee_id"`
	Assignee   *User `gorm:"foreignKey:AssigneeID" json:"assignee,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Comments []Comment `gorm:"foreignKey:TicketID" json:"comments,omitempty"`
}

type Comment struct {
	ID        uint      `gorm:"primaryKey"`
	Body      string    `json:"body"`
	TicketID  uint      `json:"ticket_id"`
	UserID    uint      `json:"user_id"`
	User      User      `json:"user,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type RefreshToken struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    uint      `gorm:"not null;index" json:"user_id"`
	User      User      `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Token     string    `gorm:"type:text;not null;uniqueIndex" json:"-"`
	ExpiresAt time.Time `gorm:"not null;index" json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
