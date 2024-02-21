package misc

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

// CallApi calls the API with the specified HTTP verb, URL, payload, user ID, and password.
//
// It returns a pointer to http.Response and an error.
func CallApi(verb string, url string, payload string, userId string, password string) (*http.Response, error) {
	if os.Getenv("API_USERID") == "" || os.Getenv("API_USERPWD") == "" {
		return nil, fmt.Errorf("missing API_USERID or API_USERPWD environment variable")
	}

	//fmt.Printf("--------- call %s:%s\n", verb, url)
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: customTransport}

	bodyReader := bytes.NewReader([]byte(payload))
	req, err := http.NewRequest(verb, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	// if credentials defined, pass them
	if userId != "" {
		req.SetBasicAuth(userId, password)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error calling %s: %s", url, err.Error())
		return nil, err
	}

	return resp, nil
}

// GetPerson retrieves a person by their ID.
//
// It takes a string parameter persId and returns a pointer to api.Person, an int, and an error.
func GetPerson(persId string) (*api.Person, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/persons/%s", persId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	// unmarshall response
	var entity api.Person
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, 0, err
	}

	return &entity, res.StatusCode, nil
}

// GetUnit retrieves a unit by its ID.
//
// unitId string - the ID of the unit to retrieve.
// *api.Unit, int, error - returns the unit, status code, and any error encountered.
func GetUnit(unitId string) (*api.Unit, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/units/%s", unitId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	// unmarshall response
	var entity api.Unit
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, 0, err
	}

	return &entity, res.StatusCode, nil
}

// GetAccred retrieves an Accred from the API.
//
// accredId is a string formated like persId:unitId
// *api.Accred, int, error
func GetAccred(accredId string) (*api.Accred, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/accreds/%s", accredId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	// unmarshall response
	var entity api.Accred
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, 0, err
	}

	return &entity, res.StatusCode, nil
}

type AccredsResponse struct {
	Accreds []*api.Accred `json:"accreds"`
	Count   int64         `json:"count"`
}

// GetAccreds retrieves accreditations for the given persons and unit IDs.
//
// Parameters:
// - persIds string: the person IDs (scipers separated by a comma)
// - unitIds string: the unit IDs (unit IDs separated by a comma)
//
// Return type(s):
// - []*api.Accred: slice of accreditations
// - int64: count of accreditations
// - int: response http status code
// - error: any error that occurred
func GetAccreds(persIds string, unitIds string) ([]*api.Accred, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/accreds?persid=%s&unitid=%s", persIds, unitIds), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, 0, err
	}

	// unmarshall response
	var entities AccredsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, 0, err
	}

	return entities.Accreds, entities.Count, res.StatusCode, nil
}

// GetAccredsFromUrl retrieves accreditations from the given URL.
//
// url: the URL to retrieve accreditations from.
// []*api.Accred, int64, int, error: returns a slice of accreditations, total count, response status code, and any error encountered.
func GetAccredsFromUrl(url string) ([]*api.Accred, int64, int, error) {
	res, err := CallApi("GET", url, "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, 0, err
	}

	// unmarshall response
	var entities AccredsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, 0, err
	}

	return entities.Accreds, entities.Count, res.StatusCode, nil
}

type AuthorizationsResponse struct {
	Authorizations []*api.Authorization `json:"authorizations"`
	Count          int64                `json:"count"`
}

// GetAuthorizations retrieves authorizations based on provided parameters.
//
// Parameters:
// - persIds string: the person IDs (scipers separated by a comma)
// - resIds string: the resource IDs (resource IDs separated by a comma)
// - authType string: the authorization type (right, role, property, status)
// - authIds string: the authorization IDs (authorization IDs or names separated by a comma)
//
// Return type(s):
// []*api.Authorization: slice of authorizations
// int64: count of authorizations
// int: response http status code
// error: any error that occurred
func GetAuthorizations(persIds string, resIds string, authType string, authIds string) ([]*api.Authorization, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/authorizations?persid=%s&resid=%s&type=%s&authid=%s", persIds, resIds, authType, authIds), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
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

// GetAuthorizationsFromUrl retrieves authorizations from the given URL.
//
// Parameter(s):
// - url string - the URL to fetch authorizations from
//
// Return type(s):
//   - []*api.Authorization: slice of authorizations
//   - int64: count of authorizations
//   - int: HTTP status code
//   - error: any error that occurred during the process
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

// checkEnvironment checks the environment for required variables.
//
// Returns an error if something's wrong
func checkEnvironment() error {
	if os.Getenv("API_GATEWAY_URL") == "" {
		return fmt.Errorf("missing API_GATEWAY_URL environment variable, possible values are 'https://api-test.epfl.ch', 'https://api-preprod.epfl.ch', 'https://api.epfl.ch'")
	}
	return nil
}
