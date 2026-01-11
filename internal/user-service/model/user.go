package model

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	Email     string         `gorm:"uniqueIndex;not null" json:"email" validate:"required,email"`
	Phone     string         `gorm:"uniqueIndex;size:20" json:"phone" validate:"omitempty,min=10"`
	Password  string         `gorm:"not null" json:"-"`
	FirstName string         `gorm:"size:100" json:"first_name" validate:"required,min=2"`
	LastName  string         `gorm:"size:100" json:"last_name" validate:"required,min=2"`
	Role      string         `gorm:"size:50;default:user" json:"role"`
	IsActive  bool           `gorm:"default:true" json:"is_active"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type RegisterRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Phone     string `json:"phone" validate:"omitempty,min=10"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required,min=2"`
	LastName  string `json:"last_name" validate:"required,min=2"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type UserResponse struct {
	ID        uint   `json:"id"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role"`
	IsActive  bool   `json:"is_active"`
}

type VerifyCredentialsResponse struct {
	UserID   uint   `json:"user_id"`
	Role     string `json:"role"`
	IsActive bool   `json:"is_active"`
	Valid    bool   `json:"valid"`
}