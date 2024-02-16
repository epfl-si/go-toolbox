package api

import "time"

type Member struct {
	GroupId   string     `json:"-"`
	MemberId  string     `json:"id"`
	Display   string     `json:"display,omitempty"`
	Email     string     `json:"email,omitempty"`
	Type      string     `json:"type,omitempty"`
	Username  string     `json:"username,omitempty"`
	OpenedBy  string     `json:"-"`
	ClosedBy  string     `json:"-"`
	ValidFrom time.Time  `json:"-"`
	ValidTo   *time.Time `json:"-"`
}
