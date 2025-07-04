package api

import "time"

type Position struct {
	Id             int        `json:"id"`
	LabelFr        string     `json:"labelfr"`
	LabelEn        string     `json:"labelen"`
	LabelXX        string     `json:"labelxx"`
	LabelInclusive string     `json:"labelinclusive"`
	Restricted     bool       `json:"restricted"`
	ValidFrom      time.Time  `json:"-"`
	ValidTo        *time.Time `json:"-"`
}
