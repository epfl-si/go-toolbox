package api

type Phone struct {
	Id               int    `json:"id"`
	Number           string `json:"number"`
	Type             string `json:"type"`
	OwnerId          int    `json:"ownerid"`
	Comment          string `json:"comment"`
	OutgoingRight    string `json:"outgoingright"`
	Billable         int    `json:"billable"`
	Internal         int    `json:"internal"`
	AttributionLabel string `json:"attributionlabel"`
}
