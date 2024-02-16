package api

import "time"

type Role struct {
	Id              int        `json:"id"`
	Name            string     `json:"name"`
	UnitType        string     `json:"unittype"`
	LabelFr         string     `json:"labelfr"`
	LabelEn         string     `json:"labelen"`
	Description     string     `json:"description"`
	NeedReval       string     `json:"needreval"`
	UnitLevels      string     `json:"unitlevels"`
	DeputiesRightId int        `json:"deputiesrightid"`
	DeputiesRight   *Right     `json:"deputiesright,omitempty"`
	HasRights       string     `json:"hasrights"`
	Delegate        string     `json:"delegate"`
	Protected       string     `json:"protected"`
	Order           int        `json:"ordre"`
	MailList        string     `json:"maillist"`
	ManagedRights   []*Right   `json:"managedrights,omitempty"`
	ManagingRights  []*Right   `json:"managingrights,omitempty"`
	ValidFrom       time.Time  `json:"-"`
	ValidTo         *time.Time `json:"-"`
}
