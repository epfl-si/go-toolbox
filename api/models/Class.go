package api

import "time"

type Class struct {
	Id          int        `json:"id"`
	Name        string     `json:"name"`
	LabelFr     string     `json:"labelfr"`
	LabelEn     string     `json:"labelen"`
	Description string     `json:"description"`
	Maillist    string     `json:"maillist"`
	StatusId    int        `json:"statusid"`
	ValidFrom   time.Time  `json:"-"`
	ValidTo     *time.Time `json:"-"`
}
