package api

type Room struct {
	Id          int       `json:"id"`
	Name        string    `json:"name"`
	BuildingId  int       `json:"buildingid"`
	Building    *Building `json:"building,omitempty"`
	StationPost int       `json:"stationpost"`
	CF4         string    `json:"cf4"`
	Unit        *Unit     `json:"unit,omitempty"`
}
