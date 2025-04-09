package api

type ListV2 struct {
	Address      string   `json:"address"`
	Id           string   `json:"id"`
	Type         string   `json:"type"`
	SubType      string   `json:"subtype"`
	Unit         string   `json:"unit"`
	UnitId       int      `json:"unitid"`
	UsualCode    string   `json:"usualcode"`
	MembersCount int      `json:"memberscount"`
	Members      []Person `json:"members,omitempty"`
}
