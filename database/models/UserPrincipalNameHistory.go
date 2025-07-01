package database

import "time"

type UserPrincipalNameHistory struct {
	PersId    string    `gorm:"column:persid;primaryKey"`
	UPN       string    `gorm:"column:upn;primaryKey"`
	CreatedAt time.Time `gorm:"primaryKey"`
}

func (balise *UserPrincipalNameHistory) TableName() string {
	return "dinfo.user_principal_name_history"
}
