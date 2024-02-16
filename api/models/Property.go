package api

import "time"

type Property struct {
	Id          int        `json:"id"`
	Name        string     `json:"name"`
	LabelFr     string     `json:"labelfr"`
	LabelEn     string     `json:"labelen"`
	Description string     `json:"description"`
	ValidFrom   time.Time  `json:"-"`
	ValidTo     *time.Time `json:"-"`
}
