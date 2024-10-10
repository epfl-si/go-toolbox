package api

import "time"

type Unit struct {
	Id             int       `json:"id"`
	Name           string    `json:"name"`
	NameEn         string    `json:"nameen"`
	NameDe         string    `json:"namede"`
	NameIt         string    `json:"nameit"`
	LabelFr        string    `json:"labelfr"`
	LabelEn        string    `json:"labelen"`
	LabelDe        string    `json:"labelde"`
	LabelIt        string    `json:"labelit"`
	StartDate      time.Time `json:"startdate"`
	Enddate        time.Time `json:"enddate"`
	Path           string    `json:"path"`
	Level          int       `json:"level"`
	ParentId       int       `json:"parentid"`
	Type           string    `json:"type"`
	ResponsibleId  string    `json:"responsibleid"`
	Responsible    *Person   `json:"responsible"`
	ComplementType string    `json:"complementtype"`
	UnitTypeId     int       `json:"unittypeid"`
	UnitType       *UnitType `json:"unittype"`
	Address1       string    `json:"address1"`
	Address2       string    `json:"address2"`
	Address3       string    `json:"address3"`
	Address4       string    `json:"address4"`
	City           string    `json:"city"`
	Country        string    `json:"country"`
	CF             string    `json:"cf"`
	Level1ID       string    `json:"level1id"`
	Level2ID       string    `json:"level2id"`
	Level3ID       string    `json:"level3id"`
	Level4ID       string    `json:"level4id"`
	Level1CF       string    `json:"level1cf"`
	Level2CF       string    `json:"level2cf"`
	Level3CF       string    `json:"level3cf"`
	Level4CF       string    `json:"level4cf"`
	PathCF         string    `json:"pathcf"`
	URL            string    `json:"url"`
	DirectChildren string    `json:"directchildren"`
	AllChildren    string    `json:"allchildren"`
	Gid            int       `json:"gid"`
	Ancestors      []string  `json:"ancestors"`
}
