package api

type Fund struct {
	Id      string `json:"id"`
	Label   string `json:"label"`
	CF      string `json:"cf"`
	OwnerId string `json:"ownerid"`
	Clients string `json:"clients"`
	Motif   string `json:"motif"`
	UnitId  int    `json:"unitid"`
}
