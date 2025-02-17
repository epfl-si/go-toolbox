package api

type Context struct {
	UserId          string
	UserType        string
	Lang            string
	Scopes          []string
	IsRoot          bool
	UserIdOverrided string // for seeAs functionality
}
