package api

type Address struct {
	PersId        int    `json:"persid"`
	UnitId        string `json:"unitid"`
	Type          string `json:"type"`
	TypeRelatedId int    `json:"typerelatedid,omitempty"`
	Address       string `json:"address,omitempty"`
	Country       string `json:"country,omitempty"`
	Part1         string `json:"part1,omitempty"`
	Part2         string `json:"part2,omitempty"`
	Part3         string `json:"part3,omitempty"`
	Part4         string `json:"part4,omitempty"`
	Part5         string `json:"part5,omitempty"`
	RoomUnitId    int    `json:"roomunitid,omitempty"`
	FromDefault   int    `json:"fromdefault"`
}
