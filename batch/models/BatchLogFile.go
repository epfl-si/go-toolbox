package batch

type BatchLogFile struct {
	Name       string `gorm:"column:filename;primaryKey" json:"name"`
	Data       []byte `gorm:"column:data" json:"data"`
	DataBase64 string `gorm:"-" json:"database64"`
}

func (balise *BatchLogFile) TableName() string {
	return "cadi.batch_logfiles"
}
