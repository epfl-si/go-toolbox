package api

type Person struct {
	Id             string         `json:"id,omitempty"`
	Display        string         `json:"display"`
	Firstname      string         `json:"firstname"`
	Lastname       string         `json:"lastname,omitempty"`
	FirstnameMaj   string         `json:"firstnameuc"`
	LastnameMaj    string         `json:"lastnameuc,omitempty"`
	FirstnameUsual string         `json:"firstnameusual,omitempty"`
	LastnameUsual  string         `json:"lastnameusual,omitempty"`
	Email          string         `json:"email,omitempty"`
	PhysEmail      string         `json:"physemail,omitempty"`
	Account        *Account       `json:"account,omitempty"`
	Username       string         `json:"username,omitempty"`
	Rooms          []*PersonRoom  `json:"rooms,omitempty"`
	Phones         []*PersonPhone `json:"phones,omitempty"`
	Addresses      []*Address     `json:"addresses,omitempty"`
	CamiproObject  *Camipro       `json:"camipro,omitempty"`
	Automap        *Automap       `json:"automap,omitempty"`
	Accreds        []*Accred      `json:"accreds"`
	Position       *Position      `json:"position,omitempty"`
	Org            string         `json:"org"`
	Gender         string         `json:"gender,omitempty"`
	SwitchAAIUser  *SwitchAAIUser `json:"switchaaiuser,omitempty"`
	Studies        []*ISAEtu      `json:"studies,omitempty"`
	Status         string         `json:"status"`
	Nebis          string         `json:"nebis,omitempty"`
}
