package api

// https://tools.ietf.org/html/rfc7807
type Error struct {
	Type     string `json:"type,omitempty"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	Help     string `json:"help,omitempty"`
}
