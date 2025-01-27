package api

import (
	"encoding/json"
	"fmt"
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

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/lists/%s", listId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetList: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entity api.List
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetList: Unmarshal: %s", err.Error())
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
func GetLists(ids, query, unitId, listType, subtype string) ([]*api.List, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	var resBytes []byte
	res := &http.Response{}

	// if 'ids' provided, use the POST on /getter instead of the GET endpoint to avoid URL length restrictions
	if ids != "" {
		resBytes, res, err = CallApi("POST", os.Getenv("API_GATEWAY_URL")+"/v1/lists/getter", `{"endpoint":"/v1/lists", "params": {"ids":"`+ids+`"}}`, os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
		if err != nil {
			return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetLists: CallApi: %s", err.Error())
		}
	} else {
		resBytes, res, err = CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/lists?ids=%s&query=%s&unitid=%s&type=%s&subtype=%s", ids, query, unitId, listType, subtype), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
		if err != nil {
			return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetLists: CallApi: %s", err.Error())
		}
	}

	// unmarshall response
	var entities ListsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetLists: Unmarshal: %s", err.Error())
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

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/lists/%s/members", id), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetListMembers: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities ListMembersResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetListMembers: Unmarshal: %s", err.Error())
	}

	return entities.Members, res.StatusCode, nil
}
