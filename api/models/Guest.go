package api

import "time"

type Guest struct {
	Id           string     `json:"id"`
	Lastname     string     `json:"lastname"`
	Firstname    string     `json:"firstname"`
	Display      string     `json:"display"`
	Email        string     `json:"email"`
	Organization string     `json:"organization"`
	AuthProvider string     `json:"-"`
	Creator      string     `json:"creator"`
	CreatedAt    *time.Time `json:"createdat"`
	ActivatedAt  *time.Time `json:"activatedat"`
	RenewedAt    *time.Time `json:"renewedat"`
	RemindedAt   *time.Time `json:"remindedat"`
	Remover      string     `json:"remover"`
	RemovedAt    *time.Time `json:"removedat"`
	Locked       bool       `json:"locked"`
	Status       string     `json:"status"`
}
