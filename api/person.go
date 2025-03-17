package api

import (
	"encoding/json"
	"fmt"
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
		return nil, http.StatusBadRequest, err
	}

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/persons/%s", persId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetPerson: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entity api.Person
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetPerson: Unmarshal: %s", err.Error())
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
func GetPersons(query, firstname, lastname, unitIds string, isAccredited bool) ([]*api.Person, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var resBytes []byte
	res := &http.Response{}

	// if 'ids' provided, use the POST on /getter instead of the GET endpoint to avoid URL length restrictions
	isAccreditedValue := "0"
	if isAccredited {
		isAccreditedValue = "1"
	}
	resBytes, res, err = CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/persons?query=%s&firstname=%s&lastname=%s&isaccredited=%s&unitid=%s", query, firstname, lastname, isAccreditedValue, unitIds), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetPersons: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities PersonsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetPersons: Unmarshal: %s", err.Error())
	}

	return entities.Persons, entities.Count, res.StatusCode, nil
}

// GetPersonsPost retrieves persons.
//
// Parameters:
// - ids string: comma separated list of person ids to retrieve
//
// Return type(s):
// - []*api.Person: accred positions
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetPersonsByIds(ids string) ([]*api.Person, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("POST", os.Getenv("API_GATEWAY_URL")+"/v1/getter", `{"endpoint":"/v1/persons", "params": {"ids":"`+ids+`"}}`, os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetPersonsByIds: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities PersonsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetPersonsByIds: Unmarshal: %s", err.Error())
	}

	return entities.Persons, entities.Count, res.StatusCode, nil
}
