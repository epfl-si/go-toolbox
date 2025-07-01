package database

import "time"

type UserPrincipalName struct {
	PersId    string `gorm:"column:persid;primaryKey"`
	UPN       string `gorm:"column:upn"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (balise *UserPrincipalName) TableName() string {
	return "dinfo.user_principal_name"
}
