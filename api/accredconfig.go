package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

// GetRight: retrieves a right
//
// Parameters:
// - idOrName string: ID or name of the right
//
// Return type(s):
// - *api.Right: accred right
// - int: response http status code
// - error: any error encountered
func GetRight(idOrName string) (*api.Right, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/config/rights/%s", idOrName), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetRight: CallApi: %s", err.Error())
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetRight: ReadAll: %s", err.Error())
	}

	// unmarshall response
	var entity api.Right
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetRight: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}

type RightsResponse struct {
	Rights []*api.Right `json:"rights"`
	Count  int64        `json:"count"`
}

// GetRights: retrieves rights
//
// Parameters:
// - search string: string to search for
//
// Return type(s):
// - []*api.Right: accred rights
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetRights(search string) ([]*api.Right, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/config/rights?search=%s", search), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetRights: CallApi: %s", err.Error())
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetRights: ReadAll: %s", err.Error())
	}

	// unmarshall response
	var entities RightsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetRights: Unmarshal: %s", err.Error())
	}

	return entities.Rights, entities.Count, res.StatusCode, nil
}

// GetRole: retrieves a role
//
// Parameters:
// - idOrName string: ID or name of the role
//
// Return type(s):
// - *api.Role: accred role
// - int: response http status code
// - error: any error encountered
func GetRole(idOrName string) (*api.Role, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/config/roles/%s", idOrName), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetRole: CallApi: %s", err.Error())
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetRole: ReadAll: %s", err.Error())
	}

	// unmarshall response
	var entity api.Role
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetRole: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}

type RolesResponse struct {
	Roles []*api.Role `json:"roles"`
	Count int64       `json:"count"`
}

// GetRoles: retrieves roles
//
// Parameters:
// - search string: string to search for
//
// Return type(s):
// - []*api.Role: accred roles
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetRoles(search string) ([]*api.Role, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/config/roles?search=%s", search), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetRoles: CallApi: %s", err.Error())
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetRoles: ReadAll: %s", err.Error())
	}

	// unmarshall response
	var entities RolesResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetRoles: Unmarshal: %s", err.Error())
	}

	return entities.Roles, entities.Count, res.StatusCode, nil
}

// GetStatus: retrieves a status
//
// Parameters:
// - idOrName string: ID or name of the status
//
// Return type(s):
// - *api.Status: accred status
// - int: response http status code
// - error: any error encountered
func GetStatus(idOrName string) (*api.Status, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/config/statuses/%s", idOrName), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetStatus: CallApi: %s", err.Error())
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetStatus: ReadAll: %s", err.Error())
	}

	// unmarshall response
	var entity api.Status
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetStatus: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}

type StatusesResponse struct {
	Statuses []*api.Status `json:"statuses"`
	Count    int64         `json:"count"`
}

// GetStatuses: retrieves statuses
//
// Parameters:
// - search string: string to search for
//
// Return type(s):
// - []*api.Status: accred statuses
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetStatuses(search string) ([]*api.Status, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/config/statuses?search=%s", search), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetStatuses: CallApi: %s", err.Error())
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetStatuses: ReadAll: %s", err.Error())
	}

	// unmarshall response
	var entities StatusesResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetStatuses: Unmarshal: %s", err.Error())
	}

	return entities.Statuses, entities.Count, res.StatusCode, nil
}

// GetProperty: retrieves a property
//
// Parameters:
// - idOrName string: ID or name of the property
//
// Return type(s):
// - *api.Property: accred property
// - int: response http status code
// - error: any error encountered
func GetProperty(idOrName string) (*api.Property, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/config/properties/%s", idOrName), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetProperty: CallApi: %s", err.Error())
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetProperty: ReadAll: %s", err.Error())
	}

	// unmarshall response
	var entity api.Property
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetProperty: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}

type PropertiesResponse struct {
	Properties []*api.Property `json:"properties"`
	Count      int64           `json:"count"`
}

// GetProperties: retrieves properties
//
// Parameters:
// - search string: string to search for
//
// Return type(s):
// - []*api.Property: accred properties
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetProperties(search string) ([]*api.Property, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/config/properties?search=%s", search), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetProperties: CallApi: %s", err.Error())
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetProperties: ReadAll: %s", err.Error())
	}

	// unmarshall response
	var entities PropertiesResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetProperties: Unmarshal: %s", err.Error())
	}

	return entities.Properties, entities.Count, res.StatusCode, nil
}

// GetPosition: retrieves a position
//
// Parameters:
// - id int: ID of the position
//
// Return type(s):
// - *api.Position: accred position
// - int: response http status code
// - error: any error encountered
func GetPosition(id int) (*api.Position, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/config/positions/%d", id), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetPosition: CallApi: %s", err.Error())
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetPosition: ReadAll: %s", err.Error())
	}

	// unmarshall response
	var entity api.Position
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetPosition: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}

type PositionsResponse struct {
	Positions []*api.Position `json:"positions"`
	Count     int64           `json:"count"`
}

// GetPositions: retrieves positions
//
// Parameters:
// - search string: string to search for
// - restricted bool: only show restricted positions
// - unitId string: only show available positions for this unit
//
// Return type(s):
// - []*api.Position: accred positions
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetPositions(search string, restricted bool, unitId int) ([]*api.Position, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	restrictedValue := "0"
	if restricted {
		restrictedValue = "1"
	}
	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/config/properties?search=%s&restricted=%s&unitid=%d", search, restrictedValue, unitId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetPositions: CallApi: %s", err.Error())
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetPositions: ReadAll: %s", err.Error())
	}

	// unmarshall response
	var entities PositionsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetPositions: Unmarshal: %s", err.Error())
	}

	return entities.Positions, entities.Count, res.StatusCode, nil
}
