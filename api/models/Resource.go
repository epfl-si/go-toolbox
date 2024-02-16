package api

import "time"

type Resource struct {
	Id             string     `json:"id"`
	Name           string     `json:"name"`
	AltName        string     `json:"altname,omitempty"`
	LabelFr        string     `json:"-"`
	LabelEn        string     `json:"-"`
	StartDate      *time.Time `json:"-"`
	Enddate        *time.Time `json:"-"`
	Path           string     `json:"path"`     // Path contains resource IDs, like "10000 12635 13028 14290" or "FC1028 FCxxxx"
	SortPath       string     `json:"sortpath"` // SortPath contains sigles for units like "EPFL VPO-SI ISCS ISCS-IAM"
	Level          int        `json:"level"`
	ParentId       string     `json:"parentid,omitempty"`
	Type           string     `json:"type"`
	ResponsibleId  string     `json:"-"`
	Responsible    *Person    `json:"responsible"`
	CF             string     `json:"cf"`
	Level1ID       string     `json:"-"`
	Level2ID       string     `json:"-"`
	Level3ID       string     `json:"-"`
	Level4ID       string     `json:"-"`
	Level1CF       string     `json:"-"`
	Level2CF       string     `json:"-"`
	Level3CF       string     `json:"-"`
	Level4CF       string     `json:"-"`
	PathCF         string     `json:"pathcf,omitempty"`
	DirectChildren []string   `json:"-"`
	AllChildren    []string   `json:"-"`
	Ancestors      []string   `json:"-"`
	OrgId          string     `json:"-"`
	ComplementType []string   `json:"-"`
}
