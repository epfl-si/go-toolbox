package api

// https://tools.ietf.org/html/rfc9457
type Error struct {
	Type     string        `json:"type,omitempty"`
	Title    string        `json:"title"`
	Status   int           `json:"status"`
	Detail   string        `json:"detail,omitempty"`
	Instance string        `json:"instance,omitempty"`
	Help     string        `json:"help,omitempty"`
	Errors   []ErrorDetail `json:"errors,omitempty"`
}
