package database

import (
	"github.com/PhilHem/go-saml-reverse-proxy/backend/config"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Init() error {
	var err error
	DB, err = gorm.Open(sqlite.Open(config.C.DatabasePath), &gorm.Config{})
	if err != nil {
		return err
	}
	return DB.AutoMigrate(&models.User{}, &models.LogEntry{})
}
