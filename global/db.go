package global

import (
	"fmt"
	"os"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() error {
	// 确保 data 目录存在
	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	db, err := gorm.Open(sqlite.Open("data/scan.db"), &gorm.Config{})
	if err != nil {
		fmt.Println(err)
		return err
	}

	if err := db.AutoMigrate(&ScanTask{}, &ScanResult{}); err != nil {
		fmt.Println(err)
		return err
	}

	DB = db
	return nil
}
