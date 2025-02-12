package batch

import (
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

type BatchConfig struct {
	StartTime   time.Time
	Uuid        string
	Name        string
	Args        string
	Stdout      string
	Stderr      string
	Status      string
	Path        string
	OutputPath  string
	FilePattern string
	Mode        string
	Logger      *zap.Logger
	Db          *gorm.DB
}
