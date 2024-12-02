package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

// GetList: retrieves a list by its ID or name
//
// Parameters:
// - listId string: the ID or name of the list to retrieve.
//
// Return type(s):
// - *api.List: the list
// - int: response http status code
// - error: any error encountered
func GetList(listId string) (*api.List, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/lists/%s", listId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// unmarshall response
	var entity api.List
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return &entity, res.StatusCode, nil
}

type ListsResponse struct {
	Lists []*api.List `json:"lists"`
	Count int64       `json:"count"`
}

// GetLists: search lists
//
// Parameters:
// - query string: search query
// - unitid string: unit ID of the lists
// - type string: type of lists (personnel, batiment, roles, droits, classes, etc.)
// - subtype string: subtype of lists (assistants, enseignants, etc.)
//
// Return type(s):
// - []*api.List: the matching lists
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetLists(query string, unitId string, listType string, subtype string) ([]*api.List, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/lists?query=%s&unitid=%s&type=%s&subtype=%s", query, unitId, listType, subtype), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	// unmarshall response
	var entities ListsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	return entities.Lists, entities.Count, res.StatusCode, nil
}

type ListMembersResponse struct {
	Members []*api.Person `json:"members"`
}

// GetListMembers: get members of a list
//
// Parameters:
// - id string: list ID
//
// Return type(s):
// - []*api.Person: the members of the list
// - int: response http status code
// - error: any error encountered
func GetListMembers(id string) ([]*api.Person, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/lists/%s/members", id), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// unmarshall response
	var entities ListMembersResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return entities.Members, res.StatusCode, nil
}
