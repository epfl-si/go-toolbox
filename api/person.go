package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

// GetPerson: retrieves a person by their ID
//
// Parameters:
// - persId string: the ID or name of the list to retrieve.
//
// Return type(s):
// - *api.Person: the person
// - int: response http status code
// - error: any error encountered
func GetPerson(persId string) (*api.Person, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/persons/%s", persId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// unmarshall response
	var entity api.Person
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return &entity, res.StatusCode, nil
}

type PersonsResponse struct {
	Persons []*api.Person `json:"persons"`
	Count   int64         `json:"count"`
}

// GetPersons retrieves persons.
//
// Parameters:
// - persIds string: persIds to search for
// - firstname string: search by firstname
// - lastname string: search by lastname
// - unitIds string: search by unitIds
// - isAccredited bool: only accredited persons
//
// Return type(s):
// - []*api.Person: accred positions
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetPersons(persIds string, firstname string, lastname string, unitIds string, isAccredited bool) ([]*api.Person, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	isAccreditedValue := "0"
	if isAccredited {
		isAccreditedValue = "1"
	}
	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/persons?persid=%s&firstname=%s&lastname=%s&isaccredited=%s&unitid=%s", persIds, firstname, lastname, isAccreditedValue, unitIds), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	// unmarshall response
	var entities PersonsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	return entities.Persons, entities.Count, res.StatusCode, nil
}
