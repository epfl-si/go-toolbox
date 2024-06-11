package api

import "time"

type Group struct {
	Id           string     `json:"id"`
	NumId        int        `json:"numid"`
	Name         string     `json:"name"`
	OwnerId      string     `json:"ownerid"`
	Description  string     `json:"description"`
	Url          string     `json:"url"`
	Access       string     `json:"access"`
	Registration string     `json:"registration"`
	VisibleStr   string     `json:"-"`
	Visible      bool       `json:"visible"`
	MaillistStr  string     `json:"-"`
	Maillist     bool       `json:"maillist"`
	VisilistStr  string     `json:"-"`
	Visilist     bool       `json:"visilist"`
	ListextStr   string     `json:"-"`
	Listext      bool       `json:"listext"`
	PublicStr    string     `json:"-"`
	Public       bool       `json:"public"`
	LdapStr      string     `json:"-"`
	Ldap         bool       `json:"ldap"`
	Gid          int        `json:"gid"`
	CreatedAt    *time.Time `json:"createdat"`
	OpenedBy     string     `json:"-"`
	ClosedBy     string     `json:"-"`
	ValidFrom    *time.Time `json:"-"`
	ValidTo      *time.Time `json:"-"`
	Owner        *Person    `json:"owner,omitempty"`
}
