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
		return nil, 0, err
	}

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	// unmarshall response
	var entity api.Service
	err = json.Unmarshal(resBytes, &entity)
	if err != nil {
		return nil, 0, err
	}

	return &entity, res.StatusCode, nil
}
