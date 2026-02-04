package api

import "time"

type AGAPerson struct {
	PersId             string     `json:"persid"`
	LastNameUppercase  string     `json:"lastname_upper"`
	FirstNameUppercase string     `json:"firstname_upper"`
	ACS                string     `json:"acs"`
	LastName           string     `json:"lastname"`
	FirstName          string     `json:"firstname"`
	Birthdate          string     `json:"birthdate"`
	Gender             string     `json:"gender"`
	CreationDate       time.Time  `json:"creation_date"`
	Creator            string     `json:"creator"`
	ModificationDate   *time.Time `json:"modification_date"`
	Editor             *string    `json:"editor"`
	FirstNameUsual     *string    `json:"firstname_usual"`
	LastNameUsual      *string    `json:"lastname_usual"`
}
