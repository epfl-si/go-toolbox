package api

type PersonRoom struct {
	PersId         string `json:"persid"`
	UnitId         string `json:"unitid"`
	RoomId         int    `json:"id"`
	Hidden         int    `json:"hidden"`
	Order          int    `json:"order"`
	ExternalRoomId int    `json:"externalroomid"`
	Room           *Room  `json:"room,omitempty"`
	Name           string `json:"name"`
	FromDefault    int    `json:"fromdefault"`
}
