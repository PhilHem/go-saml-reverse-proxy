package models

import "time"

type LogEntry struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"created_at" gorm:"index"`
	Level     string    `json:"level" gorm:"index"`
	Message   string    `json:"message"`
	Source    string    `json:"source" gorm:"index"`
	UserID    *uint     `json:"user_id" gorm:"index"`
	User      *User     `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Data      string    `json:"data"`
}

