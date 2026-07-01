package ad

import (
	"cmp"
	"crypto/tls"
	"fmt"
	"os"

	"github.com/go-ldap/ldap/v3"
)

/*
BindAD connects to an Active Directory server through LDAP protocol
- ldapURL example : "ldaps://exdev.epfl.ch" (with ldaps, port 636 is induced)
*/
func BindAD(ldapURL, bindUsername, bindPassword string) (*ldap.Conn, error) {

	// Take the first non empty value
	ldapURL = cmp.Or(ldapURL, os.Getenv("AD_SERVER_URL"))
	if ldapURL == "" {
		return nil, fmt.Errorf("missing AD_SERVER_URL environment variable")
	}

	// Take the first non empty value
	bindUsername = cmp.Or(bindUsername, os.Getenv("AD_USER"))
	if bindUsername == "" && os.Getenv("AD_USER") == "" {
		return nil, fmt.Errorf("missing AD_USER environment variable")
	}

	// Take the first non empty value
	bindPassword = cmp.Or(bindPassword, os.Getenv("AD_PWD"))
	if bindPassword == "" && os.Getenv("AD_PWD") == "" {
		return nil, fmt.Errorf("missing AD_PWD environment variable")
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	l, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(tlsConfig))
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
