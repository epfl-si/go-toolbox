package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

// GetGuest: retrieves a guest by their ID
//
// Parameters:
// - id string: the ID or email of the guest to retrieve.
//
// Return type(s):
// - *api.Guest: the guest
// - int: response http status code
// - error: any error encountered
func GetGuest(id string) (*api.Guest, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/guests/%s", id), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetGuest: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entity api.Guest
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetGuest: Unmarshal: %s", err.Error())
	}

	return &entity, res.StatusCode, nil
}

type GuestsResponse struct {
	Guests []*api.Guest `json:"guests"`
	Count  int64        `json:"count"`
}

// GetGuests retrieves guests.
//
// Parameters:
// - query string: search by name of email
// - status string: comma separated list of guest statuses ('active', 'disabled', 'pendingactivation'), default/empty is 'all statusers'
//
// Return type(s):
// - []*api.Guest: guests list
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetGuests(query string, status string) ([]*api.Guest, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/guests?query=%s&status=%s", query, status), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetGuests: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities GuestsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetGuests: Unmarshal: %s", err.Error())
	}

	return entities.Guests, entities.Count, res.StatusCode, nil
}

// GetGuestsByIds retrieves guests.
//
// Parameters:
// - ids string: comma separated list of guest ids to retrieve
//
// Return type(s):
// - []*api.Guest: guests list
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetGuestsByIds(ids string) ([]*api.Guest, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusBadRequest, err
	}

	var resBytes []byte
	res := &http.Response{}

	resBytes, res, err = CallApi("POST", os.Getenv("API_GATEWAY_URL")+"/v1/getter", `{"endpoint":"/v1/guests", "params": {"ids":"`+ids+`"}}`, os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetGuestsByIds: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities GuestsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetGuestsByIds: Unmarshal: %s", err.Error())
	}

	return entities.Guests, entities.Count, res.StatusCode, nil
}
