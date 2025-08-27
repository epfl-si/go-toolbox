package api

type PrivateEmail struct {
	PersId string `json:"persid"`
	Email  string `json:"email"`
	Status bool   `json:"status"`
	Source string `json:"source"`
}
