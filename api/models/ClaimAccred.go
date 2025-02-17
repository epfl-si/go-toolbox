package api

type ClaimAccred struct {
	UnitId     string `json:"unitid"`
	UnitName   string `json:"unitname"`
	UnitPath   string `json:"unitpath"`
	StatusName string `json:"statusname"`
	ClassName  string `json:"classname"`
}
