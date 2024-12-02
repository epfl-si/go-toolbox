package api

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	api "github.com/epfl-si/go-toolbox/api/models"
)

// GetService: retrieves a service by its ID or name
//
// Parameters:
// - serviceId string: the ID or name of the service to retrieve
//
// Return type(s):
// - *api.Service: the service
// - int: response http status code
// - error: any error encountered
func GetService(serviceId string) (*api.Service, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/services/%s", serviceId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, res.StatusCode, err
	}

	// unmarshall response
	var entity api.Service
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, res.StatusCode, err
	}

	return &entity, res.StatusCode, nil
}

type ServicesResponse struct {
	Services []*api.Service `json:"services"`
	Count    int64          `json:"count"`
}

// GetServices: retrieves services by name, unitId, persid, network property
//
// Parameters:
// - name string: name of the service
// - unitIds string: ID of unit(s) of the service(s) to retrieve
// - persIds string: ID of person(s) managing the service(s) to retrieve
// - network string: whether network property is active or not ("0" or "1")
//
// Return type(s):
// - []*api.Service: slice of services
// - int64: count
// - int: response http status code
// - error: any error encountered
func GetServices(name string, unitIds string, persIds string, network string) ([]*api.Service, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, 0, err
	}

	res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/services?name=%s&unitid=%s&persid=%s&network=%s", name, unitIds, persIds, network), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, 0, err
	}

	// unmarshall response
	var entities ServicesResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, 0, err
	}

	return entities.Services, entities.Count, res.StatusCode, nil
}
