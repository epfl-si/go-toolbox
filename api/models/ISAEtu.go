package api

type ISAEtu struct {
	PersId       string `json:"sciper,omitempty"`
	Branch1      string `json:"branch1"`
	Branch3      string `json:"branch3"`
	StudyLevel   string `json:"studylevel,omitempty"`
	Matricule    string `json:"matricule,omitempty"`
	AccredUnitId int    `json:"accredunitid,omitempty"`
}
