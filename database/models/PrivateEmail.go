package database

type PrivateEmail struct {
	Persid string `gorm:"column:persid"`
	Email  string `gorm:"column:email"`
	Status bool   `gorm:"column:status"`
	Source string `gorm:"column:source"`
}

func (balise *PrivateEmail) TableName() string {
	return "accred.privateemails"
}
