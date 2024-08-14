package database

import "time"

type Personnel struct {
	Sciper       string    `gorm:"column:sciper"`
	PrivateEmail string    `gorm:"column:privateemail"`
	BeginDate    time.Time `gorm:"column:debval"`
}

func (balise *Personnel) TableName() string {
	return "dinfo.Personnel"
}
