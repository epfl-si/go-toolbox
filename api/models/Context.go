package api

type Context struct {
	UUID            string
	UserId          string
	UserType        string
	Lang            string
	Scopes          []string
	IsRoot          bool
	UserIdOverrided string // for seeAs functionality
	Authorizations  map[string][]string
	Accreds         []ClaimAccred
	CFs             []string
}
