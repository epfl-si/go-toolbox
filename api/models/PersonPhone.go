package api

type PersonPhone struct {
	PersId      string `json:"persid"`
	UnitId      string `json:"unitid"`
	RoomId      int    `json:"roomid"`
	OtherRoom   string `json:"roomname"`
	PhoneId     int    `json:"id"`
	Hidden      int    `json:"hidden"`
	Order       int    `json:"order"`
	Phone       *Phone `json:"phone,omitempty"`
	Number      string `json:"number"`
	FromDefault int    `json:"fromdefault"`
}
