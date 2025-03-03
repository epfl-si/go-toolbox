package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

// GetBuilding: retrieves a building by its ID or name
//
// Parameters:
// - id string: the ID or name of the building to retrieve
//
// Return type(s):
// - *api.Building: the building
// - int: response http status code
// - error: any error encountered
func GetBuilding(id string) (*api.Building, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/buildings/%s", id), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetBuilding: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entity api.Building
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetBuilding: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}

// GetRoom: retrieves a building by its ID or name
//
// Parameters:
// - id string: the ID or name of the building to retrieve
//
// Return type(s):
// - *api.Room: the building
// - int: response http status code
// - error: any error encountered
func GetRoom(id string) (*api.Room, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/rooms/%s", id), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetRoom: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entity api.Room
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetRoom: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}

type RoomsResponse struct {
	Rooms []*api.Room `json:"rooms"`
	Count int64       `json:"count"`
}

// GetRooms: retrieves rooms
//
// Parameters:
// - query string: the query to search
//
// Return type(s):
// - []*api.Room: the matching rooms
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetRooms(query string) ([]*api.Room, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/rooms?query=%s", query), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetRooms: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities RoomsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetRooms: Unmarshal: %s", err.Error())
	}

	return entities.Rooms, entities.Count, res.StatusCode, nil
}

// GetRoomsByIds: retrieves rooms
//
// Parameters:
// - ids string: comma separated list of room ids to retrieve
//
// Return type(s):
// - []*api.Room: the matching rooms
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetRoomsByIds(ids string) ([]*api.Room, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("POST", os.Getenv("API_GATEWAY_URL")+"/v1/getter", `{"endpoint":"/v1/rooms", "params": {"ids":"`+ids+`"}}`, os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetRoomsByIds: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities RoomsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetRoomsByIds: Unmarshal: %s", err.Error())
	}

	return entities.Rooms, entities.Count, res.StatusCode, nil
}

// GetSite: retrieves a building by its ID or name
//
// Parameters:
// - id string: the ID or name of the site to retrieve
//
// Return type(s):
// - *api.Site: the site
// - int: response http status code
// - error: any error encountered
func GetSite(id string) (*api.Site, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/sites/%s", id), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetSite: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entity api.Site
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetSite: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}
