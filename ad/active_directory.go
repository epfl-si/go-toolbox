package ad

import (
	"fmt"
	"os"

	"gopkg.in/ldap.v2"
)

// BindAD connects to an Active Directory server through LDAP protocol
func BindAD(ldapServer string, ldapPort int, bindUsername, bindPassword string) (*ldap.Conn, error) {
	if ldapServer == "" && os.Getenv("AD_DOMAIN") == "" {
		return nil, fmt.Errorf("missing AD_DOMAIN environment variable")
	}
	if ldapServer == "" {
		ldapServer = os.Getenv("AD_DOMAIN")
	}

	if ldapPort == 0 && os.Getenv("AD_PORT") == "" {
		return nil, fmt.Errorf("missing AD_PORT environment variable")
	}

	if bindUsername == "" && os.Getenv("AD_USER") == "" {
		return nil, fmt.Errorf("missing AD_USER environment variable")
	}
	if bindUsername == "" {
		bindUsername = os.Getenv("AD_USER")
	}

	if bindPassword == "" && os.Getenv("AD_PWD") == "" {
		return nil, fmt.Errorf("missing AD_PWD environment variable")
	}
	if bindPassword == "" {
		bindPassword = os.Getenv("AD_PWD")
	}

	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort))
	if err != nil {
		return nil, fmt.Errorf("failed to start TLS: %v", err)
	}

	err = l.Bind(bindUsername, bindPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to LDAP server: %v", err)
	}

	return l, nil
}

// SearchAD will look for items in Active Directory and return the given attributes
// Need : ldap connection as returned by BindAD
// baseDN example : DC=exdev,DC=epfl,DC=ch
// filter example : (employeeID=999999)
// attributes example : []string{"userPrincipalName", "mail", "displayName"}
func SearchAD(l *ldap.Conn, baseDN, filter string, attributes []string) (*ldap.SearchResult, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,     // filter to apply
		attributes, // list of attribute(s) to retrieve
		nil,
	)

	result, err := l.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	return result, nil
}
