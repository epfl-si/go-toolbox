package api

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

type AuthorizationsResponse struct {
	Authorizations []*api.Authorization `json:"authorizations"`
	Count          int64                `json:"count"`
}

// GetAuthorizations: retrieves authorizations based on provided parameters
//
// Parameters:
// - persIds string: the person IDs (scipers separated by a comma)
// - resIds string: the resource IDs (resource IDs separated by a comma)
// - authType string: the authorization type (right, role, property, status)
// - authIds string: the authorization IDs (authorization IDs or names separated by a comma)
//
// Return type(s):
// - []*api.Authorization: slice of authorizations
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetAuthorizations(persIds string, resIds string, authType string, authIds string) ([]*api.Authorization, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/authorizations?persid=%s&resid=%s&type=%s&authid=%s&alldata=1", persIds, resIds, authType, authIds), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, 0, err
	}

	// unmarshall response
	var entities AuthorizationsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, 0, err
	}

	return entities.Authorizations, entities.Count, res.StatusCode, nil
}

// GetAuthorizationsFromUrl: retrieves authorizations from the given URL
//
// Parameter(s):
// - url string - the URL to fetch authorizations from
//
// Return type(s):
// - []*api.Authorization: slice of authorizations
// - int64: count
// - int: HTTP status code
// - error: any error encountered
func GetAuthorizationsFromUrl(url string) ([]*api.Authorization, int64, int, error) {
	res, err := CallApi("GET", url, "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, 0, err
	}

	// unmarshall response
	var entities AuthorizationsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, 0, err
	}

	return entities.Authorizations, entities.Count, res.StatusCode, nil
}
