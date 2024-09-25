package api

type Building struct {
	Id        int    `json:"id"`
	Name      string `json:"name"`
	Label     string `json:"label"`
	Rule      string `json:"rule"`
	Site      *Site  `json:"site,omitempty"`
	SiteId    int    `json:"siteid"`
	UsualCode string `json:"usualcode"`
	Station   string `json:"station"`
	Street1   string `json:"street1"`
	Street2   string `json:"street2"`
	City      string `json:"city"`
	Number    int    `json:"number"`
	PttOrder  string `json:"pttorder"`
}
