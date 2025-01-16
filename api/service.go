package api

import (
	"encoding/json"
	"fmt"
	"net/http"
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
		return nil, http.StatusInternalServerError, err
	}

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/services/%s", serviceId), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, res.StatusCode, fmt.Errorf("go-toolbox: GetService: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entity api.Service
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetService: Unmarshal: %s", err.Error())
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
// - ids string: comma separated list of service ids to retrieve, cannot mix with other filters
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
func GetServices(ids, name, unitIds, persIds, network string) ([]*api.Service, int64, int, error) {
	err := checkEnvironment()
	if err != nil {
		return nil, 0, http.StatusInternalServerError, err
	}

	resBytes, res, err := CallApi("GET", fmt.Sprintf(os.Getenv("API_GATEWAY_URL")+"/v1/services?ids=%s&name=%s&unitid=%s&persid=%s&network=%s", ids, name, unitIds, persIds, network), "", os.Getenv("API_USERID"), os.Getenv("API_USERPWD"))
	if err != nil {
		return nil, 0, res.StatusCode, fmt.Errorf("go-toolbox: GetServices: CallApi: %s", err.Error())
	}

	// unmarshall response
	var entities ServicesResponse
	err = json.Unmarshal(resBytes, &entities)
	if err != nil {
		return nil, 0, http.StatusInternalServerError, fmt.Errorf("go-toolbox: GetServices: Unmarshal: %s", err.Error())
	}

	return entities.Services, entities.Count, res.StatusCode, nil
}
