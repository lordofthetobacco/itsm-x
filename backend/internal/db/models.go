package db

import "time"

type User struct {
	ID           uint      `gorm:"primaryKey"`
	Name         string    `json:"name"`
	Email        string    `gorm:"uniqueIndex" json:"email"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	Tickets      []Ticket  `gorm:"foreignKey:RequesterID"`
}

type Ticket struct {
	ID          uint   `gorm:"primaryKey"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Priority    string `json:"priority"`

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
