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
		return nil, http.StatusBadRequest, err
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

// GetListV2: retrieves a list by its ID or name
//
// Parameters:
// - listId string: the ID or name of the list to retrieve.
//
// Return type(s):
// - *api.ListV2: the list
// - int: response http status code
// - error: any error encountered
func GetListV2(listId string) (*api.ListV2, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v2/lists/%s", listId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetListV2: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entity api.ListV2
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetListV2: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}

type ListsResponse struct {
	Lists []*api.List `json:"lists"`
	Count int64       `json:"count"`
}
type ListsV2Response struct {
	Lists []*api.ListV2 `json:"lists"`
	Count int64         `json:"count"`
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
func GetLists(query, unitId, listType, subtype string) ([]*api.List, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/lists?query=%s&unitid=%s&type=%s&subtype=%s", query, unitId, listType, subtype), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetLists: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities ListsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetLists: Unmarshal: %s", err.Error())
	}

	return entities.Lists, entities.Count, res.StatusCode, nil
}

// GetListsV2: search lists
//
// Parameters:
// - query string: search query
// - unitid string: unit ID of the lists
// - type string: type of lists (personnel, batiment, roles, droits, classes, etc.)
// - subtype string: subtype of lists (assistants, enseignants, etc.)
//
// Return type(s):
// - []*api.ListV2: the matching lists
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetListsV2(query, unitId, listType, subtype string) ([]*api.ListV2, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v2/lists?query=%s&unitid=%s&type=%s&subtype=%s", query, unitId, listType, subtype), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetLGetListsV2sts: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities ListsV2Response
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetListsV2: Unmarshal: %s", err.Error())
	}

	return entities.Lists, entities.Count, res.StatusCode, nil
}

// GetListsByIds: search lists
//
// Parameters:
// - ids string: comma separated list of list ids to retrieve
// - unitid string: unit ID of the lists
// - type string: type of lists (personnel, batiment, roles, droits, classes, etc.)
// - subtype string: subtype of lists (assistants, enseignants, etc.)
//
// Return type(s):
// - []*api.List: the matching lists
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetListsByIds(ids string) ([]*api.List, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("POST", os.Getenv("API_GATEWAY_URL")+"/v1/getter", `{"endpoint":"/v1/lists", "params": {"ids":"`+ids+`"}}`, os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetListsByIds: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities ListsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetListsByIds: Unmarshal: %s", err.Error())
	}

	return entities.Lists, entities.Count, res.StatusCode, nil
}

// GetListsV2ByIds: search lists
//
// Parameters:
// - ids string: comma separated list of list ids to retrieve
// - unitid string: unit ID of the lists
// - type string: type of lists (personnel, batiment, roles, droits, classes, etc.)
// - subtype string: subtype of lists (assistants, enseignants, etc.)
//
// Return type(s):
// - []*api.ListV2: the matching lists
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetListsV2ByIds(ids string) ([]*api.ListV2, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("POST", os.Getenv("API_GATEWAY_URL")+"/v1/getter", `{"endpoint":"/v2/lists", "params": {"ids":"`+ids+`"}}`, os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetListsV2ByIds: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities ListsV2Response
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetListsV2ByIds: Unmarshal: %s", err.Error())
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
		return nil, http.StatusBadRequest, err
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
