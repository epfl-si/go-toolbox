package batch

import "time"

type BatchLog struct {
	Id           string    `gorm:"column:id;primaryKey" json:"id"`
	Date         time.Time `gorm:"column:date" json:"date"`
	Name         string    `gorm:"column:name" json:"name"`
	Args         string    `gorm:"column:args" json:"args"`
	Stdout       string    `gorm:"column:stdout" json:"stdout"`
	Stderr       string    `gorm:"column:stderr" json:"stderr"`
	StdoutLength int       `gorm:"column:stdout_length" json:"stdout_length"`
	StderrLength int       `gorm:"column:stderr_length" json:"stderr_length"`
	Status       string    `gorm:"column:status" json:"status"`
	Path         string    `gorm:"column:path" json:"path"`
	LastChange   time.Time `gorm:"column:last_change" json:"last_change"`
	OutputPath   string    `gorm:"column:output_path" json:"output_path"`
	FilePattern  string    `gorm:"column:file_pattern" json:"file_pattern"`
	Mode         string    `gorm:"column:mode" json:"mode"`
}

func (balise *BatchLog) TableName() string {
	return "cadi.batch_logs"
}
