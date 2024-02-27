package api

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

// GetUnit: retrieves a unit by its ID or name
//
// Parameters:
// - unitId string: the ID or name of the unit to retrieve
//
// Return type(s):
// - *api.Unit: the unit
// - int: response http status code
// - error: any error encountered
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

type UnitsResponse struct {
	Units []*api.Unit `json:"units"`
	Count int64       `json:"count"`
}

// GetUnits: retrieves units
//
// Parameters:
// - query string: the query to search
//
// Return type(s):
// - []*api.Unit: the matching units
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetUnits(query string) ([]*api.Unit, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/units?query=%s", query), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, 0, err
	}

	// unmarshall response
	var entities UnitsResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, 0, err
	}

	return entities.Units, entities.Count, res.StatusCode, nil
}
