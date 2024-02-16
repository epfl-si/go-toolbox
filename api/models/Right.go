package api

import "time"

type Right struct {
	Id            int        `json:"id"`
	Name          string     `json:"name"`
	UnitType      string     `json:"unittype"`
	UnitLevels    string     `json:"unitlevels"`
	LabelFr       string     `json:"labelfr"`
	LabelEn       string     `json:"labelen"`
	Description   string     `json:"description"`
	NeedReval     string     `json:"needreval"`
	Order         int        `json:"ordre"`
	Url           string     `json:"url"`
	ManagingRoles []*Role    `json:"managingroles,omitempty"` // which roles are managing this right
	ManagedRoles  []*Role    `json:"managedroles,omitempty"`  // which roles does this right manage
	ValidFrom     time.Time  `json:"-"`
	ValidTo       *time.Time `json:"-"`
}
