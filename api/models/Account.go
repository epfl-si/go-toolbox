package api

type Account struct {
	Id       int    `json:"sciper"`
	Username string `json:"username"`
	Uid      int    `json:"uid"`
	Gid      int    `json:"gid"`
	Home     string `json:"home"`
	Shell    string `json:"shell"`
	Gecos    string `json:"gecos"`
}
