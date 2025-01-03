package models

type Event struct {
	UUID      string            `json:"uuid"`
	EventType string            `json:"type"`
	Args      map[string]string `json:"args"`
	Status    int               `json:"status"`
	Requester string            `json:"author"`
	App       string            `json:"app"`
}
