package api

import "time"

type UserPrincipalName struct {
	PersId    string    `json:"persid"`
	UPN       string    `json:"upn"`
	Type      string    `json:"type"`
	SynchroAD bool      `json:"synchro_ad"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
