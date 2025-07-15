package api

type Email struct {
	PersId  string `json:"persid"`
	Email   string `json:"email"`
	Addrphy string `json:"addrphy"`
	Type    string `json:"type"`
}
