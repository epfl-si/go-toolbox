package api

import "time"

type Status struct {
	Id          int        `json:"id"`
	Name        string     `json:"name"`
	LabelFr     string     `json:"labelfr"`
	LabelEn     string     `json:"labelen"`
	Description string     `json:"description"`
	Maillist    string     `json:"maillist"`
	Classes     []*Class   `json:"classes"`
	ValidFrom   time.Time  `json:"-"`
	ValidTo     *time.Time `json:"-"`
}
