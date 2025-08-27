package api

type PrivateEmailsResponse struct {
	PrivateEmails []PrivateEmail `json:"emails"`
	Count         int64          `json:"count"`
}
