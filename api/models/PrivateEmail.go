package api

import "time"

type PrivateEmail struct {
	PersId    string    `json:"persid"`
	Email     string    `json:"email"`
	Status    bool      `json:"status"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}
