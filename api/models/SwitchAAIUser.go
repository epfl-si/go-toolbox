package api

type SwitchAAIUser struct {
	Id        string `json:"id,omitempty"`
	Firstname string `json:"firstname"`
	Username  string `json:"username,omitempty"`
	Email     string `json:"email,omitempty"`
	Org       string `json:"org,omitempty"`
}
