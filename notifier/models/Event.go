package models

type Event struct {
	UUID      string            `gorm:"column:uuid;primaryKey" json:"uuid"`
	EventType string            `gorm:"column:type" json:"type"`
	Args      map[string]string `gorm:"-" json:"args"`
	ArgsStr   string            `gorm:"column:args" json:"-"`
	Status    int               `gorm:"column:status" json:"status"`
}

func (balise *Event) TableName() string {
	return "events"
}
