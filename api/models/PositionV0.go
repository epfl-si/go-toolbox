package api

import "time"

type PositionV0 struct {
	Id             int        `json:"id"`
	LabelFr        string     `json:"labelfr"`
	LabelEn        string     `json:"labelen"`
	LabelXX        string     `json:"labelxx"`
	LabelInclusive string     `json:"labelinclusive"`
	Restricted     string     `json:"restricted"`
	ValidFrom      time.Time  `json:"-"`
	ValidTo        *time.Time `json:"-"`
}
