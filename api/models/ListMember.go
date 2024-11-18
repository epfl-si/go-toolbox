package api

type ListMember struct {
	ListId        int    `json:"id"`
	PersId        string `json:"sciper"`
	Email         string `json:"email"`
	Firstname     string `json:"firstname"`
	Lastname      string `json:"lastname"`
	FistnameUsual string `json:"firstnameusual"`
	LastnameUsual string `json:"lastnameusual"`
	Display       string `json:"display"`
	Username      string `json:"username"`
}
