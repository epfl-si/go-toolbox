package api

import "time"

type Camipro struct {
	PersId       string    `json:"sciper"`
	CardId       string    `json:"cardid"`
	BiblioId     string    `json:"biblioid"`
	CardStatus   string    `json:"cardstatus"`
	PersStatus   string    `json:"persstatus"`
	EmissionDate time.Time `json:"emissiondate"`
	StateDate    time.Time `json:"statedate"`
}
