package batch

import (
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type BatchConfig struct {
	Uuid        string
	Name        string
	Args        string
	Stdout      string
	Stderr      string
	Status      string
	Path        string
	OutputPath  string
	FilePattern string
	Logger      *zap.Logger
	Db          *gorm.DB
}
