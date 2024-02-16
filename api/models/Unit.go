package api

type Unit struct {
	Id       int    `json:"id"`
	Name     string `json:"name"`
	CF       string `json:"cf"`
	LabelFr  string `json:"labelfr"`
	LabelEn  string `json:"labelen"`
	Address1 string `json:"address1"`
	Address2 string `json:"address2"`
	Address3 string `json:"address3"`
	Address4 string `json:"address4"`
	City     string `json:"city"`
}
