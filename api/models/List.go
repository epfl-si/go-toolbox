package api

type List struct {
	Address      string   `json:"address"`
	Id           int      `json:"id"`
	Type         string   `json:"type"`
	SubType      string   `json:"subtype"`
	Unit         string   `json:"unit"`
	UnitId       int      `json:"unitid"`
	UsualCode    string   `json:"usualcode"`
	MembersCount int      `json:"memberscount"`
	Members      []Person `json:"members,omitempty"`
}
