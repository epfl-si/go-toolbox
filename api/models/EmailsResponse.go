package api

type EmailsResponse struct {
	Emails []Email `json:"emails"`
	Count  int64   `json:"count"`
}
