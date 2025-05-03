package api

type Homonym struct {
	Fullname     string   `json:"fullname"`
	PrimaryId    string   `json:"primaryid"`
	SecondaryIds []string `json:"secondaryids"`
}
