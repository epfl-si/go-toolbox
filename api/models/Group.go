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
	Visible      int        `json:"visible"`
	MaillistStr  string     `json:"-"`
	Maillist     int        `json:"maillist"`
	VisilistStr  string     `json:"-"`
	Visilist     int        `json:"visilist"`
	ListextStr   string     `json:"-"`
	Listext      int        `json:"listext"`
	PublicStr    string     `json:"-"`
	Public       int        `json:"public"`
	LdapStr      string     `json:"-"`
	Ldap         int        `json:"ldap"`
	Gid          int        `json:"gid"`
	CreatedAt    *time.Time `json:"createdat"`
	OpenedBy     string     `json:"-"`
	ClosedBy     string     `json:"-"`
	ValidFrom    *time.Time `json:"-"`
	ValidTo      *time.Time `json:"-"`
	Owner        *Person    `json:"owner,omitempty"`
}
