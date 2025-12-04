package database

import (
	"todo-app/backend/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Init() error {
	var err error
	DB, err = gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	if err != nil {
		return err
	}
	return DB.AutoMigrate(&models.User{}, &models.LogEntry{})
}
