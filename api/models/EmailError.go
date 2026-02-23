package api

type EmailError struct {
	Message        string `json:"message"`
	RequestedEmail Email  `json:"requested_email"`
	Status         int    `json:"status"`
}
