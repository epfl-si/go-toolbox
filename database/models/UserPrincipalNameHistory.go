package database

import "time"

type UserPrincipalNameHistory struct {
	PersId    string `gorm:"column:persid"`
	UPN       string `gorm:"column:upn"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (balise *UserPrincipalNameHistory) TableName() string {
	return "dinfo.user_principal_name_history"
}
