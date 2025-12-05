package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Email      string `json:"email" gorm:"uniqueIndex"`
	Password   string `json:"-"` // hashed, never serialize
	MFAEnabled bool   `json:"mfa_enabled" gorm:"default:false"`
	MFASecret  string `json:"-"` // TOTP secret, never serialize
}



