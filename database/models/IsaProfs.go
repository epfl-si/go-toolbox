package database

import "time"

type IsaProfs struct {
	PersId    string    `gorm:"column:sciper"`
	Status    string    `gorm:"column:statut"`
	StartDate time.Time `gorm:"column:datedeb"`
	EndDate   time.Time `gorm:"column:datefin"`
}

func (balise *IsaProfs) TableName() string {
	return "dinfo.isa_profs"
}
