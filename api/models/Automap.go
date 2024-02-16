package api

type Automap struct {
	Id       string `json:"sciper"`
	Protocol string `json:"protocol"`
	Server   string `json:"server"`
	Path     string `json:"path"`
	Security string `json:"security"`
}
